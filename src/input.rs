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
