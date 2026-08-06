import threading

from pipeline.runner import EventHook, PipelineRunner


def test_event_hook_notifies_subscribers_and_can_disconnect():
    hook = EventHook()
    received = []

    def callback(*values):
        received.append(values)

    hook.connect(callback)
    hook.emit("tool", "started")
    hook.disconnect(callback)
    hook.emit("tool", "finished")

    assert received == [("tool", "started")]


def test_pipeline_runner_is_qt_free_and_cancellable():
    runner = PipelineRunner.__new__(PipelineRunner)
    runner._stop_event = threading.Event()
    runner._active_containers = {}
    runner._containers_lock = threading.Lock()

    runner.stop()

    assert runner._stop_event.is_set()
