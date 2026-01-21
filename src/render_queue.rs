use crate::cache::SingleflightPermit;
use crate::render::{
    render_token_uncached, RenderKeyLimit, RenderResponse, RenderQueueError, RenderRequest,
};
use crate::state::AppState;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};

pub struct RenderJob {
    pub request: RenderRequest,
    pub width: Option<u32>,
    pub variant_key: String,
    pub singleflight_permit: SingleflightPermit,
    pub key_limit: Option<RenderKeyLimit>,
    pub respond_to: oneshot::Sender<Result<RenderResponse>>,
}

pub fn spawn_workers(
    state: Arc<AppState>,
    receiver: mpsc::Receiver<RenderJob>,
    workers: usize,
) {
    let receiver = Arc::new(Mutex::new(receiver));
    let worker_count = workers.max(1);
    for _ in 0..worker_count {
        let state = state.clone();
        let receiver = receiver.clone();
        tokio::spawn(async move {
            loop {
                let job = {
                    let mut guard = receiver.lock().await;
                    guard.recv().await
                };
                let Some(job) = job else { break };
                let RenderJob {
                    request,
                    width,
                    variant_key,
                    singleflight_permit,
                    key_limit,
                    respond_to,
                } = job;
                let result = run_job(
                    state.clone(),
                    request,
                    width,
                    variant_key,
                    singleflight_permit,
                    key_limit,
                )
                .await;
                let _ = respond_to.send(result);
            }
        });
    }
}

async fn run_job(
    state: Arc<AppState>,
    request: RenderRequest,
    width: Option<u32>,
    variant_key: String,
    singleflight_permit: SingleflightPermit,
    key_limit: Option<RenderKeyLimit>,
) -> Result<RenderResponse> {
    let _singleflight = singleflight_permit;
    let _key_permit = if let Some(limit) = key_limit {
        Some(
            state
                .key_render_limiter
                .acquire(limit.key_id, limit.max_concurrent)
                .await?,
        )
    } else {
        None
    };
    let _permit = state.render_semaphore.acquire().await?;
    render_token_uncached(&state, &request, width, &variant_key).await
}

pub fn try_enqueue(
    sender: &mpsc::Sender<RenderJob>,
    job: RenderJob,
) -> Result<(), RenderQueueError> {
    sender
        .try_send(job)
        .map_err(|_| RenderQueueError::QueueFull)
}
