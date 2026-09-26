//! Bracketed-paste framing and terminal path parsing.

pub const START: &[u8] = b"\x1b[200~";
pub const END: &[u8] = b"\x1b[201~";
pub const MAX_PASTE: usize = 64 * 1024;
const MAX_PATHS: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum Part {
    Bytes(Vec<u8>),
    Paste(Vec<u8>),
}

/// Position relative to terminal control strings (OSC, DCS, APC, PM, SOS).
/// Terminal replies, such as a window title report, can echo guest-controlled
/// text inside such a string. Paste markers there must not trigger imports.
#[derive(Clone, Copy, Default, PartialEq)]
enum Control {
    #[default]
    Ground,
    Escape,
    String,
    StringEscape,
}

impl Control {
    fn next(self, byte: u8) -> Self {
        match (self, byte) {
            // BEL and ST terminate a string. CAN and SUB abort it.
            (Self::String | Self::StringEscape, 0x07 | 0x18 | 0x1a)
            | (Self::StringEscape, b'\\') => Self::Ground,
            (Self::String | Self::StringEscape, 0x1b) => Self::StringEscape,
            (Self::String | Self::StringEscape, _)
            | (Self::Escape, b']' | b'P' | b'_' | b'^' | b'X') => Self::String,
            (_, 0x1b) => Self::Escape,
            _ => Self::Ground,
        }
    }
}

/// Splits input into pass-through bytes and paste bodies. Marker bytes pass
/// through at once, because the filter never changes them. Only a paste body
/// waits for its end marker.
#[derive(Default)]
pub struct Decoder {
    /// Matched length of the current marker: END in a paste or bypass, else START.
    seen: usize,
    paste: Option<Vec<u8>>,
    bypass: bool,
    control: Control,
}

/// Marker progress after `byte`. Neither marker repeats its first byte, so a
/// mismatch can only restart the match at that byte.
fn advance(marker: &[u8], seen: usize, byte: u8) -> usize {
    if byte == marker[seen] {
        seen + 1
    } else {
        usize::from(byte == marker[0])
    }
}

impl Decoder {
    /// Partial state that the idle timeout must end.
    pub fn is_pending(&self) -> bool {
        self.seen > 0 || self.paste.is_some() || self.control != Control::Ground
    }

    pub fn in_paste(&self) -> bool {
        self.paste.is_some()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Part> {
        let mut out = Vec::new();
        let mut raw = Vec::new();
        for &byte in bytes {
            if let Some(paste) = &mut self.paste {
                paste.push(byte);
                self.seen = advance(END, self.seen, byte);
                if self.seen == END.len() {
                    self.seen = 0;
                    let mut paste = self.paste.take().expect("paste exists");
                    paste.truncate(paste.len() - END.len());
                    if !raw.is_empty() {
                        out.push(Part::Bytes(std::mem::take(&mut raw)));
                    }
                    out.push(Part::Paste(paste));
                } else if paste.len() - self.seen > MAX_PASTE {
                    raw.extend(self.paste.take().expect("paste exists"));
                    self.bypass = true;
                }
                continue;
            }
            raw.push(byte);
            if self.bypass {
                self.seen = advance(END, self.seen, byte);
                if self.seen == END.len() {
                    self.seen = 0;
                    self.bypass = false;
                }
                continue;
            }
            if matches!(self.control, Control::String | Control::StringEscape) {
                self.control = self.control.next(byte);
                continue;
            }
            self.control = self.control.next(byte);
            self.seen = advance(START, self.seen, byte);
            if self.seen == START.len() {
                self.seen = 0;
                self.paste = Some(Vec::new());
            }
        }
        if !raw.is_empty() {
            out.push(Part::Bytes(raw));
        }
        out
    }

    /// Bypass the rest of an interrupted paste so its tail cannot trigger imports.
    pub fn flush(&mut self) -> Vec<u8> {
        self.control = Control::Ground;
        if let Some(paste) = self.paste.take() {
            self.bypass = true;
            return paste;
        }
        if !self.bypass {
            self.seen = 0;
        }
        Vec::new()
    }
}

/// Parse a paste as absolute paths. Terminals quote dropped paths for the
/// shell, but file managers copy unquoted paths, one per line.
pub fn paths(text: &[u8]) -> Option<Vec<String>> {
    shell_words(text).or_else(|| literal_lines(text))
}

/// Parse shell-quoted absolute paths without expanding variables or substitutions.
fn shell_words(text: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(text).ok()?;
    if text.chars().any(char::is_control) {
        return None;
    }
    let mut paths = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;
    for c in text.chars() {
        if escaped {
            if quote == Some('"') && !matches!(c, '$' | '`' | '"' | '\\') {
                word.push('\\');
            }
            word.push(c);
            escaped = false;
        } else if c == '\\' && quote != Some('\'') {
            escaped = true;
        } else if quote == Some(c) {
            quote = None;
        } else if quote.is_some() {
            word.push(c);
        } else if c == '\'' || c == '"' {
            quote = Some(c);
        } else if c == ' ' {
            if !word.is_empty() {
                paths.push(std::mem::take(&mut word));
            }
        } else {
            word.push(c);
        }
    }
    if quote.is_some() || escaped {
        return None;
    }
    if !word.is_empty() {
        paths.push(word);
    }
    if paths.is_empty() || paths.len() > MAX_PATHS || paths.iter().any(|p| !p.starts_with('/')) {
        return None;
    }
    Some(paths)
}

/// Terminals send the line breaks of a paste as CR, so every line ending counts.
fn literal_lines(text: &[u8]) -> Option<Vec<String>> {
    let text = std::str::from_utf8(text).ok()?;
    let text = text.trim_end_matches(['\r', '\n']);
    let paths: Vec<String> = text
        .split("\r\n")
        .flat_map(|line| line.split(['\r', '\n']))
        .map(str::to_owned)
        .collect();
    if paths.len() > MAX_PATHS
        || paths
            .iter()
            .any(|p| !p.starts_with('/') || p.chars().any(char::is_control))
    {
        return None;
    }
    Some(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode(parts: Vec<Part>) -> Vec<u8> {
        let mut out = Vec::new();
        for part in parts {
            match part {
                Part::Bytes(bytes) => out.extend(bytes),
                Part::Paste(bytes) => {
                    out.extend(bytes);
                    out.extend_from_slice(END);
                }
            }
        }
        out
    }

    fn pastes(parts: Vec<Part>) -> Vec<Vec<u8>> {
        parts
            .into_iter()
            .filter_map(|part| match part {
                Part::Paste(bytes) => Some(bytes),
                Part::Bytes(_) => None,
            })
            .collect()
    }

    #[test]
    fn marker_bytes_pass_through_without_waiting() {
        let mut decoder = Decoder::default();
        for byte in START.iter().chain(b"/a") {
            let parts = decoder.feed(&[*byte]);
            if b"/a".contains(byte) {
                assert!(parts.is_empty());
            } else {
                assert_eq!(parts, [Part::Bytes(vec![*byte])]);
            }
        }
        assert_eq!(pastes(decoder.feed(END)), [b"/a".to_vec()]);
    }

    #[test]
    fn every_chunk_boundary_preserves_input_and_detects_paste() {
        let input = b"before\x1b[200~/tmp/a.png\x1b[201~\rafter";
        for split in 0..=input.len() {
            let mut decoder = Decoder::default();
            let mut parts = decoder.feed(&input[..split]);
            parts.extend(decoder.feed(&input[split..]));
            assert!(parts.contains(&Part::Paste(b"/tmp/a.png".to_vec())));
            assert_eq!(encode(parts), input);
            assert!(decoder.flush().is_empty());
        }
    }

    #[test]
    fn byte_at_a_time_and_consecutive_pastes() {
        let input = b"\x1b[200~/a\x1b[201~\x1b[200~/b\x1b[201~";
        let mut decoder = Decoder::default();
        let parts: Vec<_> = input.iter().flat_map(|b| decoder.feed(&[*b])).collect();
        assert_eq!(pastes(parts), [b"/a".to_vec(), b"/b".to_vec()]);
    }

    #[test]
    fn incomplete_and_oversized_pastes_are_lossless() {
        for input in [
            b"\x1b".to_vec(),
            b"a\x1b[200~/a\x1b[20".to_vec(),
            [START, &vec![b'x'; MAX_PASTE + 100], END, b"\r"].concat(),
        ] {
            let mut decoder = Decoder::default();
            let mut out = encode(decoder.feed(&input));
            out.extend(decoder.flush());
            assert_eq!(out, input);
        }
    }

    #[test]
    fn timed_out_paste_tail_cannot_import() {
        let mut decoder = Decoder::default();
        decoder.feed(b"\x1b[200~unfinished");
        decoder.flush();
        let parts = decoder.feed(b"\x1b[200~/secret\x1b[201~");
        assert!(parts.iter().all(|p| matches!(p, Part::Bytes(_))));
    }

    #[test]
    fn arbitrary_bytes_and_chunk_sizes_are_lossless() {
        let mut seed = 12345_u32;
        for _ in 0..200 {
            let mut input = Vec::new();
            for _ in 0..100 {
                seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                match seed % 8 {
                    0 => input.extend_from_slice(START),
                    1 => input.extend_from_slice(END),
                    2 => input.extend_from_slice(b"\x1b]"),
                    3 => input.extend_from_slice(b"\x1b\\"),
                    4 => input.push(0x07),
                    _ => input.extend_from_slice(&seed.to_le_bytes()),
                }
            }
            let mut decoder = Decoder::default();
            let mut out = Vec::new();
            for chunk in input.chunks((seed as usize % 17) + 1) {
                out.extend(encode(decoder.feed(chunk)));
            }
            out.extend(decoder.flush());
            assert_eq!(out, input);
        }
    }

    #[test]
    fn paste_markers_inside_terminal_replies_are_plain_bytes() {
        for input in [
            b"\x1b]l\x1b[200~/secret\x1b[201~\x1b\\".as_slice(),
            b"\x1b]10;\x1b[200~/secret\x1b[201~\x07",
            b"\x1bP1$r\x1b[200~/secret\x1b[201~\x1b\\",
        ] {
            let mut decoder = Decoder::default();
            assert_eq!(decoder.feed(input), [Part::Bytes(input.to_vec())]);
            assert!(!decoder.is_pending());
            assert_eq!(
                pastes(decoder.feed(b"\x1b[200~/a\x1b[201~")),
                [b"/a".to_vec()]
            );
        }
    }

    #[test]
    fn unterminated_terminal_string_ends_at_flush() {
        let mut decoder = Decoder::default();
        assert_eq!(decoder.feed(b"\x1b]"), [Part::Bytes(b"\x1b]".to_vec())]);
        assert!(decoder.is_pending());
        assert!(decoder.flush().is_empty());
        assert_eq!(
            pastes(decoder.feed(b"\x1b[200~/a\x1b[201~")),
            [b"/a".to_vec()]
        );
    }

    #[test]
    fn lexes_terminal_paths_without_evaluating_them() {
        assert_eq!(
            paths(r#"'/tmp/a b.png' /tmp/c\ d.png "/tmp/猫.png" "#.as_bytes()),
            Some(vec![
                "/tmp/a b.png".into(),
                "/tmp/c d.png".into(),
                "/tmp/猫.png".into()
            ])
        );
        for input in [
            "describe /tmp/a.png",
            "relative.png",
            "/a\n\n/b",
            "/a\r relative",
            "'/a",
            "file:///a",
            "",
            "/a\0",
        ] {
            assert_eq!(paths(input.as_bytes()), None, "{input:?}");
        }
        assert_eq!(
            paths(b"'/tmp/$(touch owned).png'"),
            Some(vec!["/tmp/$(touch owned).png".into()])
        );
    }

    #[test]
    fn unquoted_file_manager_paths_are_read_line_by_line() {
        assert_eq!(
            paths(b"/home/me/Pictures/Screenshot 2026.png"),
            Some(vec!["/home/me/Pictures/Screenshot 2026.png".into()])
        );
        for separator in ["\r", "\n", "\r\n"] {
            let input = format!("/home/me/a b.png{separator}/home/me/it's.png{separator}");
            assert_eq!(
                paths(input.as_bytes()),
                Some(vec!["/home/me/a b.png".into(), "/home/me/it's.png".into()]),
                "{separator:?}"
            );
        }
        // Taken literally, text after a path is part of a file name. The
        // import then fails and forwards the paste unchanged.
        assert_eq!(
            paths(b"/home/me/a.png is broken"),
            Some(vec!["/home/me/a.png is broken".into()])
        );
    }

    #[test]
    fn double_quotes_preserve_literal_backslashes() {
        assert_eq!(
            paths(br#""/tmp/a\b.png" "/tmp/a\\b.png" "/tmp/a\"b.png" "/tmp/\$file.png""#),
            Some(vec![
                r"/tmp/a\b.png".into(),
                r"/tmp/a\b.png".into(),
                "/tmp/a\"b.png".into(),
                "/tmp/$file.png".into(),
            ])
        );
    }
}
