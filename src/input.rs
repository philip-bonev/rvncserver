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
