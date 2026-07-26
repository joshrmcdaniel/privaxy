//! The `GM_*` API surface a userscript sees, and the proxy-side machinery
//! behind it.
//!
//! Userscripts run in the page's main world, because a proxy has no isolated
//! world to offer. Anything they need from Privaxy therefore has to be reachable
//! from page context — and a page cannot send credentials to the Privaxy origin
//! without CORS, which this codebase deliberately does not enable on `/api`. So
//! the pieces here are served on *the page's own origin* and intercepted before
//! the request is forwarded upstream:
//!
//! - [`endpoint`] routes the reserved `/__privaxy__/gm/*` paths.
//! - [`token`] authorizes them, and documents precisely what that authorization
//!   does and does not prove. Read it before changing any of the others.
//! - [`storage`] persists `GM_setValue` data.
//! - [`fetch`] performs `GM_xmlhttpRequest` server-side — the most dangerous
//!   code in the engine, since the proxy's network position is not the browser's.
//!
//! The in-page half lives in `resources/userscript_shim.js`; the script store and
//! matching live in [`super::userscripts`].

pub(crate) mod endpoint;
pub(crate) mod fetch;
pub(crate) mod storage;
pub(crate) mod token;
