"""Qt compatibility wrapper for the framework-neutral PipelineRunner."""

from PySide6.QtCore import QThread, Signal

from pipeline.runner import PipelineRunner


class PipelineExecutor(QThread):
    session_started = Signal(str)
    step_started = Signal(str, str, int)
    step_log = Signal(str, str)
    step_done = Signal(str, str, int)
    stage_done = Signal(int)
    pipeline_done = Signal(str, bool, str)
    progress = Signal(int, int)

    def __init__(self, *args, **kwargs):
        super().__init__()
        self._runner = PipelineRunner(*args, **kwargs)
        self._runner.session_started.connect(self.session_started.emit)
        self._runner.step_started.connect(self.step_started.emit)
        self._runner.step_log.connect(self.step_log.emit)
        self._runner.step_done.connect(self.step_done.emit)
        self._runner.stage_done.connect(self.stage_done.emit)
        self._runner.pipeline_done.connect(self.pipeline_done.emit)
        self._runner.progress.connect(self.progress.emit)

    def run(self):
        self._runner.run()

    def stop(self):
        self._runner.stop()

    def stop_tool(self, tool_key: str):
        self._runner.stop_tool(tool_key)

    def add_tool_keys(self, tool_keys: set[str]) -> bool:
        return self._runner.add_tool_keys(tool_keys)

    @property
    def session_id(self) -> str:
        return self._runner._session_id

    def __getattr__(self, name):
        """Preserve read access used by legacy monitoring code during migration."""
        runner = self.__dict__.get("_runner")
        if runner is not None:
            return getattr(runner, name)
        raise AttributeError(name)
