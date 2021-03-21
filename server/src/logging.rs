use crate::LOG;
use tide::{Middleware, Next, Request, Result};

#[derive(Debug, Default, Clone)]
pub struct LogMiddleware {
    _i: (),
}

struct LogMiddlewareHasBeenRun;

/// The built in tide logging middleware doesn't let you
/// customize the message or how it's logged, so this is
/// mostly a copy but changes the logger to use slog
/// and changes the messages a bit.
impl LogMiddleware {
    #[must_use]
    pub fn new() -> Self {
        Self { _i: () }
    }

    async fn log<'a, State: Clone + Send + Sync + 'static>(
        &'a self,
        mut req: Request<State>,
        next: Next<'a, State>,
    ) -> Result {
        if req.ext::<LogMiddlewareHasBeenRun>().is_some() {
            return Ok(next.run(req).await);
        }
        req.set_ext(LogMiddlewareHasBeenRun);

        let path = req.url().path().to_owned();
        let method = req.method().to_string();
        let start = std::time::Instant::now();
        let log = LOG.new(slog::o!("method" => method, "path" => path));
        slog::debug!(log, "request received");

        let response = next.run(req).await;
        let status = response.status();
        if status.is_server_error() {
            if let Some(error) = response.error() {
                slog::error!(log, "Internal error";
                "message" => format!("{:?}", error),
                "error_type" => error.type_name(),
                );
            } else {
                slog::error!(log, "Unknown internal error");
            }
        } else if status.is_client_error() {
            if let Some(error) = response.error() {
                slog::warn!(log, "Client error";
                "message" => format!("{:?}", error),
                "error_type" => error.type_name(),
                );
            } else {
                slog::warn!(log, "Unknown client error");
            }
        }
        slog::info!(log, "handled request";
            "status" => format!("{} - {}", status as u16, status.canonical_reason()),
            "duration" => format!("{:?}", start.elapsed()),
        );
        Ok(response)
    }
}

#[async_trait::async_trait]
impl<State: Clone + Send + Sync + 'static> Middleware<State> for LogMiddleware {
    async fn handle(&self, req: Request<State>, next: Next<'_, State>) -> Result {
        self.log(req, next).await
    }
}
