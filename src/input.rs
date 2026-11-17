// Copyright 2026 Philip Bonev
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://apache.org
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! RFB-originated events forwarded to the portal session.

/// An input or clipboard event requested by the connected RFB client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    /// XKB keysym press or release.
    Key { keysym: u32, pressed: bool },
    /// Pointer position and the current RFB button mask.
    Pointer { x: u16, y: u16, buttons: u8 },
    /// Client clipboard text in the RFB Latin-1 representation.
    Clipboard(Vec<u8>),
}

/// Convert RFB Latin-1 clipboard text to UTF-8.
pub fn latin1_to_utf8(data: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|byte| char::from(*byte))
        .collect::<String>()
        .into_bytes()
}

/// Convert UTF-8 clipboard text to the RFB Latin-1 representation. Characters
/// outside Latin-1 become `?`, matching the wire format's limitations.
pub fn utf8_to_latin1(data: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(data)
        .chars()
        .map(|character| u8::try_from(u32::from(character)).unwrap_or(b'?'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_rfb_latin1_and_portal_utf8_clipboard_text() {
        assert_eq!(latin1_to_utf8(&[b'A', 0xe9]), "Aé".as_bytes());
        assert_eq!(utf8_to_latin1("Aé€".as_bytes()), [b'A', 0xe9, b'?']);
    }
}
