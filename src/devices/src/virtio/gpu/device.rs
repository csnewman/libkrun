use std::io::Write;
use std::mem::size_of;
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
use crossbeam_channel::bounded;
use utils::eventfd::EventFd;
use vm_memory::{ByteValued, GuestMemoryMmap};

#[cfg(target_os = "linux")]
use super::super::PauseError;
use super::super::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, Queue as VirtQueue, QueueConfig,
    VirtioDevice, VirtioShmRegion, fs::ExportTable,
};
use super::defs;
use super::defs::uapi;
use super::defs::uapi::virtio_gpu_config;
use super::virtio_gpu::virgl_flags_to_capsets;
use super::worker::{Restore, Worker, WorkerHandle};
use crate::display::DisplayInfo;
use crate::virtio::InterruptTransport;
use krun_display::DisplayBackend;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

// Supported features.
pub(crate) const AVAIL_FEATURES: u64 = (1u64 << uapi::VIRTIO_F_VERSION_1)
    | (1u64 << uapi::VIRTIO_GPU_F_VIRGL)
    | (1u64 << uapi::VIRTIO_GPU_F_EDID)
    | (1u64 << uapi::VIRTIO_GPU_F_RESOURCE_UUID)
    | (1u64 << uapi::VIRTIO_GPU_F_RESOURCE_BLOB)
    | (1u64 << uapi::VIRTIO_GPU_F_CONTEXT_INIT)
    | (1u64 << uapi::VIRTIO_GPU_F_BLOB_ALIGNMENT);

const QUEUE_SIZE: u16 = 256;
static QUEUE_CONFIG: [QueueConfig; defs::NUM_QUEUES] =
    [QueueConfig::new(QUEUE_SIZE); defs::NUM_QUEUES];

pub struct Gpu {
    pub(crate) avail_features: u64,
    pub(crate) acked_features: u64,
    pub(crate) device_state: DeviceState,
    shm_region: Option<VirtioShmRegion>,
    virgl_flags: u32,
    #[cfg(target_os = "macos")]
    map_sender: Sender<WorkerMessage>,
    export_table: Option<ExportTable>,
    displays: Box<[DisplayInfo]>,
    display_backend: DisplayBackend<'static>,
    blob_alignment: u32,
    worker: Option<WorkerHandle>,
    // The control queue is the worker's, the cursor queue is unused; both are
    // kept to hand back at a pause.
    control_queue: Option<(Arc<Mutex<VirtQueue>>, Arc<EventFd>)>,
    cursor_queue: Option<DeviceQueue>,
    paused: bool,
    saved: Vec<u8>,
    restore: Option<Vec<u8>>,
}

/// A copy of a queue's state, for the transport to save.
#[cfg(target_os = "linux")]
fn copy_queue(queue: &VirtQueue, event: &Arc<EventFd>) -> DeviceQueue {
    let mut copy = VirtQueue::new(queue.get_max_size());
    copy.restore(&queue.snapshot());
    DeviceQueue::new(copy, event.clone())
}

impl Gpu {
    pub fn new(
        virgl_flags: u32,
        displays: Box<[DisplayInfo]>,
        display_backend: DisplayBackend<'static>,
        #[cfg(target_os = "macos")] map_sender: Sender<WorkerMessage>,
    ) -> super::Result<Gpu> {
        Ok(Gpu {
            avail_features: AVAIL_FEATURES,
            acked_features: 0,
            device_state: DeviceState::Inactive,
            shm_region: None,
            virgl_flags,
            #[cfg(target_os = "macos")]
            map_sender,
            export_table: None,
            displays,
            display_backend,
            // Blobs are mapped into the guest in host pages, which can be
            // larger than the guest's (16 KiB on Apple silicon).
            blob_alignment: unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32,
            worker: None,
            control_queue: None,
            cursor_queue: None,
            paused: false,
            saved: Vec::new(),
            restore: None,
        })
    }

    pub fn id(&self) -> &str {
        defs::GPU_DEV_ID
    }

    pub fn set_shm_region(&mut self, shm_region: VirtioShmRegion) {
        debug!("virtio_gpu: set_shm_region");
        self.shm_region = Some(shm_region);
    }

    pub fn set_export_table(&mut self, export_table: ExportTable) {
        self.export_table = Some(export_table);
    }

    /// Leaves `VIRTIO_GPU_F_BLOB_ALIGNMENT` out of the features offered.
    pub fn withhold_blob_alignment(&mut self) {
        self.avail_features &= !(1 << uapi::VIRTIO_GPU_F_BLOB_ALIGNMENT);
    }

    /*
    pub fn process_ctl(&mut self) -> bool {
        debug!("gpu: process_ctl()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        //while let Some(head) = self.queues[CTL_INDEX].pop(mem) {
        if let Some(head) = self.queues[CTL_INDEX].pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                error!("gpu: process_ctl() unimplemented");
                self.queues[CTL_INDEX].go_to_previous_position();
                break;
            }

            have_used = true;
            self.queues[CTL_INDEX].add_used(mem, index, written);
        }

        have_used
    }

    pub fn process_cur(&mut self) -> bool {
        debug!("gpu: process_cur()");
        let mem = match self.device_state {
            DeviceState::Activated(ref mem) => mem,
            // This should never happen, it's been already validated in the event handler.
            DeviceState::Inactive => unreachable!(),
        };

        let mut have_used = false;

        while let Some(head) = self.queues[CTL_INDEX].pop(mem) {
            let index = head.index;
            let mut written = 0;
            for desc in head.into_iter() {
                error!("gpu: process_cur() unimplemented");
                self.queues[CTL_INDEX].go_to_previous_position();
                break;
            }

            have_used = true;
            self.queues[CTL_INDEX].add_used(mem, index, written);
        }

        have_used
    }
    */
}

impl VirtioDevice for Gpu {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features
    }

    fn device_type(&self) -> u32 {
        uapi::VIRTIO_ID_GPU
    }

    fn device_name(&self) -> &str {
        "gpu"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn config_len(&self) -> Option<u32> {
        Some(size_of::<virtio_gpu_config>() as u32)
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config = virtio_gpu_config {
            events_read: 0,
            events_clear: 0,
            num_scanouts: self.displays.len() as u32,
            num_capsets: virgl_flags_to_capsets(self.virgl_flags).count_ones(),
            blob_alignment: self.blob_alignment,
        };

        let config_slice = config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..std::cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        warn!(
            "gpu: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let [control_q, cursor_q]: [_; defs::NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!(
                "Cannot perform activate. Expected {} queue(s)",
                defs::NUM_QUEUES
            );
            ActivateError::BadActivate
        })?;

        let shm_region = match self.shm_region.as_ref() {
            Some(s) => s.clone(),
            None => panic!("virtio_gpu: missing SHM region"),
        };

        let control_event = control_q.event.clone();
        let worker = Worker::new(
            control_q,
            mem.clone(),
            interrupt.clone(),
            shm_region,
            self.virgl_flags,
            #[cfg(target_os = "macos")]
            self.map_sender.clone(),
            self.export_table.take(),
            self.displays.clone(),
            self.display_backend,
        );
        self.control_queue = Some((worker.control_queue(), control_event));
        self.cursor_queue = Some(cursor_q);

        let (restore, restored) = match self.restore.take() {
            Some(state) => {
                let (done, restored) = bounded(1);
                (Some(Restore { state, done }), Some(restored))
            }
            None => (None, None),
        };
        self.worker = Some(worker.run(restore));
        // Before the guest runs: the restored blobs must be in the window
        // when it next reads them.
        if let Some(restored) = restored {
            match restored.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error!("gpu: restoring its state: {e}");
                    return Err(ActivateError::BadActivate);
                }
                Err(_) => return Err(ActivateError::BadActivate),
            }
        }

        self.device_state = DeviceState::Activated(mem, interrupt);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn pause(&mut self) -> std::result::Result<Vec<DeviceQueue>, PauseError> {
        let (Some(worker), Some((control, event)), Some(cursor)) =
            (&self.worker, &self.control_queue, &self.cursor_queue)
        else {
            return Err(PauseError::Failed("gpu queues are missing".into()));
        };
        self.saved = worker.pause().map_err(PauseError::Failed)?;
        self.paused = true;
        let control = copy_queue(&control.lock().unwrap(), event);
        Ok(vec![control, copy_queue(&cursor.queue, &cursor.event)])
    }

    fn save_state(&self) -> Vec<u8> {
        self.saved.clone()
    }

    fn restore_state(&mut self, state: &[u8]) -> std::result::Result<(), crate::Error> {
        self.restore = (!state.is_empty()).then(|| state.to_vec());
        Ok(())
    }

    /// Runs a paused worker again, or on a device restored from a snapshot,
    /// starts one that first builds the saved state again.
    fn resume(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        if self.paused {
            self.paused = false;
            self.saved = Vec::new();
            if let Some(worker) = &self.worker {
                worker.resume();
            }
            return Ok(());
        }
        self.activate(mem, interrupt, queues)
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    fn shm_region(&self) -> Option<&VirtioShmRegion> {
        debug!("virtio_gpu: GET_shm_region");
        self.shm_region.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::display::NoopDisplayBackend;
    use krun_display::IntoDisplayBackend;

    #[test]
    fn blob_alignment_offered() {
        let gpu = Gpu::new(
            0,
            Box::new([]),
            NoopDisplayBackend::into_display_backend(None),
            #[cfg(target_os = "macos")]
            crossbeam_channel::unbounded().0,
        )
        .unwrap();
        assert_ne!(
            gpu.avail_features() & (1 << uapi::VIRTIO_GPU_F_BLOB_ALIGNMENT),
            0
        );
        let mut data = [0u8; 4];
        gpu.read_config(16, &mut data);
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as u32;
        assert_eq!(u32::from_le_bytes(data), page_size);
    }

    #[test]
    fn blob_alignment_withheld() {
        let mut gpu = Gpu::new(
            0,
            Box::new([]),
            NoopDisplayBackend::into_display_backend(None),
            #[cfg(target_os = "macos")]
            crossbeam_channel::unbounded().0,
        )
        .unwrap();
        gpu.withhold_blob_alignment();
        assert_eq!(
            gpu.avail_features() & (1 << uapi::VIRTIO_GPU_F_BLOB_ALIGNMENT),
            0
        );
    }
}
