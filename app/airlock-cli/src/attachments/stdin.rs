//! File-drop handling for raw, monitor and exec input.

use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use airlock_common::supervisor_capnp::{data_frame, process_input, stdin};
use futures::FutureExt;
use futures::future::LocalBoxFuture;
use tokio::sync::Mutex;

use super::Imports;
use super::paste::{Decoder, END, Part, START};

enum Input {
    Data(Vec<u8>),
    Resize(u16, u16),
    Eof,
}

#[derive(Default)]
struct State {
    decoder: Decoder,
    ready: VecDeque<Input>,
    // Cancelling a read on timeout can lose input that the source already consumed.
    pending: Option<LocalBoxFuture<'static, Result<Input, capnp::Error>>>,
    eof: bool,
}

struct Filter {
    source: stdin::Client,
    imports: Imports,
    state: Mutex<State>,
}

pub fn wrap(source: stdin::Client, imports: Option<&Imports>, interactive: bool) -> stdin::Client {
    match imports.filter(|_| interactive) {
        Some(imports) => capnp_rpc::new_client(Filter {
            source,
            imports: imports.clone(),
            state: Mutex::new(State::default()),
        }),
        None => source,
    }
}

async fn read_source(source: stdin::Client) -> Result<Input, capnp::Error> {
    let response = source.read_request().send().promise.await?;
    let input = response.get()?.get_input()?;
    Ok(match input.which()? {
        process_input::Stdin(frame) => match frame?.which()? {
            data_frame::Data(bytes) => Input::Data(bytes?.to_vec()),
            data_frame::Eof(()) => Input::Eof,
        },
        process_input::Resize(size) => {
            let size = size?;
            Input::Resize(size.get_rows(), size.get_cols())
        }
    })
}

impl stdin::Server for Filter {
    async fn read(
        self: Rc<Self>,
        _params: stdin::ReadParams,
        mut results: stdin::ReadResults,
    ) -> Result<(), capnp::Error> {
        let mut state = self.state.lock().await;
        let input = loop {
            if let Some(input) = state.ready.pop_front() {
                break input;
            }
            if state.eof {
                break Input::Eof;
            }
            if state.pending.is_none() {
                state.pending = Some(read_source(self.source.clone()).boxed_local());
            }
            let deadline = if state.decoder.in_paste() {
                Duration::from_secs(2)
            } else {
                Duration::from_millis(50)
            };
            let has_buffer = state.decoder.is_pending();
            let pending = state.pending.as_mut().expect("read is pending");
            let next = if has_buffer {
                tokio::time::timeout(deadline, pending).await.ok()
            } else {
                Some(pending.await)
            };
            let Some(next) = next else {
                let bytes = state.decoder.flush();
                if !bytes.is_empty() {
                    state.ready.push_back(Input::Data(bytes));
                }
                continue;
            };
            state.pending = None;
            match next? {
                Input::Data(bytes) => {
                    for part in state.decoder.feed(&bytes) {
                        let data = match part {
                            Part::Bytes(bytes) => bytes,
                            Part::Paste(bytes) => {
                                let rewritten = self.imports.rewrite(bytes).await;
                                [START, rewritten.as_slice(), END].concat()
                            }
                        };
                        state.ready.push_back(Input::Data(data));
                    }
                }
                Input::Resize(rows, cols) => state.ready.push_back(Input::Resize(rows, cols)),
                Input::Eof => {
                    state.eof = true;
                    let bytes = state.decoder.flush();
                    if !bytes.is_empty() {
                        state.ready.push_back(Input::Data(bytes));
                    }
                }
            }
        };
        let dest = results.get().init_input();
        match input {
            Input::Data(bytes) => dest.init_stdin().set_data(&bytes),
            Input::Resize(rows, cols) => {
                let mut size = dest.init_resize();
                size.set_rows(rows);
                size.set_cols(cols);
            }
            Input::Eof => dest.init_stdin().set_eof(()),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use super::*;
    use crate::attachments::tests::{fixture, imported_path, put};

    fn channel(
        imports: &Imports,
        interactive: bool,
    ) -> (mpsc::Sender<airlock_monitor::TuiInputEvent>, stdin::Client) {
        let (tx, rx) = mpsc::channel(16);
        let source = capnp_rpc::new_client(airlock_monitor::TuiStdin::new(rx, Some((24, 80))));
        (tx, wrap(source, Some(imports), interactive))
    }

    async fn data(client: &stdin::Client) -> Vec<u8> {
        match read_source(client.clone()).await.unwrap() {
            Input::Data(bytes) => bytes,
            _ => panic!("expected data"),
        }
    }

    #[tokio::test]
    async fn rewrites_before_enter_and_preserves_resize_and_eof() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (dir, imports) = fixture();
                let path = put(dir.path(), "external screenshot.png", b"image");
                let (tx, client) = channel(&imports, true);
                for bytes in [
                    b"\x1b[2".to_vec(),
                    format!("00~'{path}'\x1b[20").into_bytes(),
                    b"1~\r".to_vec(),
                ] {
                    tx.send(airlock_monitor::TuiInputEvent::Data(bytes))
                        .await
                        .unwrap();
                }
                tx.send(airlock_monitor::TuiInputEvent::Resize(40, 100))
                    .await
                    .unwrap();
                drop(tx);
                let output = data(&client).await;
                let guest = std::str::from_utf8(
                    output
                        .strip_prefix(START)
                        .unwrap()
                        .strip_suffix(END)
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    std::fs::read(imported_path(&imports, guest)).unwrap(),
                    b"image"
                );
                assert_eq!(data(&client).await, b"\r");
                assert!(matches!(
                    read_source(client.clone()).await.unwrap(),
                    Input::Resize(40, 100)
                ));
                assert!(matches!(read_source(client).await.unwrap(), Input::Eof));
            })
            .await;
    }

    #[tokio::test]
    async fn escape_timeout_keeps_the_outstanding_read() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (_dir, imports) = fixture();
                let (tx, client) = channel(&imports, true);
                tx.send(airlock_monitor::TuiInputEvent::Data(b"\x1b".to_vec()))
                    .await
                    .unwrap();
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), data(&client))
                        .await
                        .unwrap(),
                    b"\x1b"
                );
                tx.send(airlock_monitor::TuiInputEvent::Data(
                    b"following key".to_vec(),
                ))
                .await
                .unwrap();
                assert_eq!(data(&client).await, b"following key");
                drop(tx);
                assert!(matches!(read_source(client).await.unwrap(), Input::Eof));
            })
            .await;
    }

    #[tokio::test]
    async fn non_tty_and_unframed_input_never_import() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (dir, imports) = fixture();
                let path = put(dir.path(), "external.png", b"image");
                for (interactive, input) in [
                    (false, [START, path.as_bytes(), END].concat()),
                    (true, path.into_bytes()),
                ] {
                    let (tx, client) = channel(&imports, interactive);
                    tx.send(airlock_monitor::TuiInputEvent::Data(input.clone()))
                        .await
                        .unwrap();
                    assert_eq!(data(&client).await, input);
                }
                assert_eq!(imports.0.lock().files, 0);
            })
            .await;
    }

    #[tokio::test]
    async fn eof_flushes_incomplete_paste_without_importing() {
        tokio::task::LocalSet::new()
            .run_until(async {
                let (dir, imports) = fixture();
                let path = put(dir.path(), "external.png", b"image");
                let (tx, client) = channel(&imports, true);
                let input = [START, path.as_bytes()].concat();
                tx.send(airlock_monitor::TuiInputEvent::Data(input.clone()))
                    .await
                    .unwrap();
                drop(tx);
                assert_eq!(data(&client).await, input);
                assert!(matches!(read_source(client).await.unwrap(), Input::Eof));
                assert_eq!(imports.0.lock().files, 0);
            })
            .await;
    }
}
