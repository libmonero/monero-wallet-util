#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{
  pin::Pin,
  task::{Poll, Context},
  future::Future,
};
extern crate alloc;
use alloc::{vec::Vec, string::String};

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
  js_sys::{Reflect, Uint8Array},
  ReadableStreamDefaultReader, Request, RequestInit, Response,
};

pub use monero_daemon_rpc::prelude;
use monero_daemon_rpc::{prelude::InterfaceError, HttpTransport, MoneroDaemon};

/// An transport to connect to a Monero daemon, using the web browser's HTTP APIs.
#[derive(Clone, Debug)]
pub struct WebSysTransport {
  url: String,
}

impl WebSysTransport {
  /// Create a new RPC connection, using the web browser's HTTP APIs.
  pub fn new(
    url: String,
  ) -> impl Future<Output = Result<MoneroDaemon<WebSysTransport>, InterfaceError>> {
    MoneroDaemon::new(WebSysTransport { url })
  }
}

async fn __unsafe_internal_post(
  url: &str,
  route: &str,
  body: Vec<u8>,
  response_size_limit: Option<usize>,
) -> Result<Vec<u8>, InterfaceError> {
  let opts = RequestInit::new();
  opts.set_method("POST");
  opts.set_body(&Uint8Array::from(body.as_slice()).into());
  let request = Request::new_with_str_and_init(&(url.to_owned() + "/" + route), &opts)
    .map_err(|e| InterfaceError::InternalError(format!("failed to create request: {e:?}")))?;

  let window = web_sys::window()
    .ok_or_else(|| InterfaceError::InternalError("failed to acquire window".to_owned()))?;

  let response = JsFuture::from(window.fetch_with_request(&request)).await.map_err(|e| {
    InterfaceError::InvalidInterface(format!("failed to make request to RPC: {e:?}"))
  })?;
  if !response.is_instance_of::<Response>() {
    Err(InterfaceError::InternalError("fetch result wasn't a response".to_owned()))?;
  }
  let response: Response = response.dyn_into().expect("response type was just checked");

  // Check if response is OK
  if !response.ok() {
    return Err(InterfaceError::InvalidInterface(format!(
      "HTTP error: {} {}",
      response.status(),
      response.status_text()
    )));
  }

  /*
    Read the body as a stream so a response exceeding the size limit is rejected while being
    read. Buffering the body in full (as `array_buffer` would) would let a malicious daemon
    exhaust the tab's memory before the size was ever checked.
  */
  let stream = response.body().ok_or_else(|| {
    InterfaceError::InvalidInterface("response didn't include a body to read".to_owned())
  })?;
  let reader: ReadableStreamDefaultReader = stream.get_reader().dyn_into().map_err(|_| {
    InterfaceError::InternalError("response body couldn't be read with a default reader".to_owned())
  })?;

  let mut res = Vec::new();
  loop {
    let read = JsFuture::from(reader.read()).await.map_err(|e| {
      InterfaceError::InvalidInterface(format!("failed to read response body: {e:?}"))
    })?;
    let done = Reflect::get(&read, &JsValue::from("done"))
      .map_err(|e| InterfaceError::InternalError(format!("failed to get `done` from read: {e:?}")))?
      .as_bool()
      .ok_or_else(|| {
        InterfaceError::InternalError("read result's `done` wasn't a boolean".to_owned())
      })?;
    if done {
      break;
    }

    let chunk = Reflect::get(&read, &JsValue::from("value"))
      .map_err(|e| {
        InterfaceError::InternalError(format!("failed to get `value` from read: {e:?}"))
      })?
      .dyn_into::<Uint8Array>()
      .map_err(|_| InterfaceError::InternalError("read result wasn't a Uint8Array".to_owned()))?;
    let chunk_len = usize::try_from(chunk.length()).map_err(|_| {
      InterfaceError::InternalError("received chunk of length exceeding `usize`".to_owned())
    })?;

    if let Some(limit) = response_size_limit {
      if res.len() + chunk_len > limit {
        // Cancel the stream so the rest of the oversized response isn't received; whether the
        // cancellation succeeds is irrelevant as the response is being rejected regardless
        let _ = JsFuture::from(reader.cancel()).await;
        Err(InterfaceError::InvalidInterface(format!(
          "response exceeded the size limit of {limit} bytes"
        )))?;
      }
    }

    let start = res.len();
    res.resize(start + chunk_len, 0);
    chunk.copy_to(&mut res[start ..]);
  }

  Ok(res)
}

/// A future wrapped to claim `Send` as `HttpTransport::post` returns an `impl Send + Future`.
///
/// The wrapped future holds JS values, which aren't `Send` as JS offers no guarantees regarding
/// its objects being moved between threads. Browsers execute JS, and the WASM calling into it,
/// on a single thread, so this future will never actually be sent across a thread and the claim
/// of `Send` is vacuous. This is only sound under that single-threaded model; it would be
/// unsound if this were polled from a multi-threaded runtime (as shared-memory WASM threads
/// would allow).
#[repr(transparent)]
struct UnsafeSendFuture<F: Future>(F);
unsafe impl<F: Future> Send for UnsafeSendFuture<F> {}
impl<F: Future> Future for UnsafeSendFuture<F> {
  type Output = F::Output;
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let actual: Pin<&mut F> = unsafe { core::mem::transmute(self) };
    actual.poll(cx)
  }
}

impl HttpTransport for WebSysTransport {
  fn post(
    &self,
    route: &str,
    body: Vec<u8>,
    response_size_limit: Option<usize>,
  ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
    UnsafeSendFuture(__unsafe_internal_post(&self.url, route, body, response_size_limit))
  }
}
