use aegis_app::{AppError, WebhookDispatcher};

pub struct NoopWebhookDispatcher;

impl NoopWebhookDispatcher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoopWebhookDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl WebhookDispatcher for NoopWebhookDispatcher {
    async fn dispatch(&self, event: &str, payload: &str) -> Result<(), AppError> {
        tracing::debug!(event, payload, "noop webhook dispatch");
        Ok(())
    }
}
