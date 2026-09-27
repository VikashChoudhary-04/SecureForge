"""Tests for the SecureForge security tool executor."""

import sys
import time

import pytest

from secureforge.core.config import ToolConfiguration
from secureforge.core.scan.executor import ToolExecutor
from secureforge.core.scan.models import ToolExecutionStatus

def build_python_tool(
code: str,
*,
name: str = "PythonTest",
timeout_seconds: int = 5,
arguments: list[str] | None = None,
environment: dict[str, str] | None = None,
) -> ToolConfiguration:
"""Create a Python-based test tool configuration."""
command = [
sys.executable,
"-c",
code,
]

```
if arguments:
    command.extend(arguments)

return ToolConfiguration(
    name=name,
    enabled=True,
    command=command,
    timeout_seconds=timeout_seconds,
    environment=environment or {},
)
```

def test_executor_runs_successful_command() -> None:
"""Verify a successful subprocess execution."""
tool = build_python_tool(
"print('SecureForge test')"
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.SUCCESS
assert result.succeeded is True
assert result.failed is False
assert result.exit_code == 0
assert "SecureForge test" in result.stdout
assert result.error is None
```

def test_executor_captures_stderr() -> None:
"""Verify stderr is captured."""
tool = build_python_tool(
"import sys; sys.stderr.write('test error')"
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.SUCCESS
assert "test error" in result.stderr
```

def test_executor_handles_nonzero_exit_code() -> None:
"""Verify a non-zero exit code produces FAILED."""
tool = build_python_tool(
"import sys; sys.exit(7)"
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.FAILED
assert result.succeeded is False
assert result.failed is True
assert result.exit_code == 7
assert (
    "exited with code 7"
    in result.error
)
```

def test_executor_handles_missing_executable() -> None:
"""Verify missing executables produce a controlled failure."""
tool = ToolConfiguration(
name="MissingTool",
executable="secureforge-executable-that-does-not-exist",
timeout_seconds=5,
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.FAILED
assert result.failed is True
assert result.exit_code is None
assert (
    "was not found"
    in result.error
)
```

def test_executor_handles_timeout() -> None:
"""Verify long-running tools are terminated by timeout handling."""
tool = build_python_tool(
"import time; time.sleep(2)",
timeout_seconds=1,
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.TIMEOUT
assert result.failed is True
assert result.succeeded is False
assert (
    "exceeded the 1-second timeout"
    in result.error
)
```

def test_executor_records_duration() -> None:
"""Verify execution duration is recorded."""
tool = build_python_tool(
"print('done')"
)

```
result = ToolExecutor().execute(tool)

assert result.duration_seconds >= 0.0
```

def test_executor_records_timestamps() -> None:
"""Verify execution timestamps are populated."""
tool = build_python_tool(
"print('done')"
)

```
result = ToolExecutor().execute(tool)

assert result.started_at is not None
assert result.completed_at is not None
assert (
    result.completed_at
    >= result.started_at
)
```

def test_executor_preserves_command() -> None:
"""Verify the executed command is preserved."""
tool = build_python_tool(
"print('done')"
)

```
result = ToolExecutor().execute(tool)

assert result.command == tool.command
```

def test_executor_supports_executable_configuration() -> None:
"""Verify executable plus arguments builds correctly."""
tool = ToolConfiguration(
name="PythonExecutable",
executable=sys.executable,
arguments=[
"-c",
"print('executable mode')",
],
timeout_seconds=5,
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.SUCCESS
assert "executable mode" in result.stdout
```

def test_executor_supports_command_configuration() -> None:
"""Verify command-list configuration works."""
tool = ToolConfiguration(
name="PythonCommand",
command=[
sys.executable,
"-c",
"print('command mode')",
],
timeout_seconds=5,
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.SUCCESS
assert "command mode" in result.stdout
```

def test_executor_appends_arguments_to_command() -> None:
"""Verify configured arguments are appended."""
tool = ToolConfiguration(
name="PythonArguments",
command=[
sys.executable,
"-c",
],
arguments=[
"print('argument mode')",
],
timeout_seconds=5,
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.SUCCESS
assert "argument mode" in result.stdout
```

def test_executor_supports_environment_variables() -> None:
"""Verify configured environment variables reach the process."""
tool = build_python_tool(
"import os; print(os.environ['SECUREFORGE_TEST'])",
environment={
"SECUREFORGE_TEST": "enabled"
},
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.SUCCESS
assert "enabled" in result.stdout
```

def test_executor_preserves_tool_metadata() -> None:
"""Verify tool metadata is included in the result."""
tool = build_python_tool(
"print('metadata')"
)

```
tool.metadata = {
    "category": "test",
    "purpose": "unit-test",
}

result = ToolExecutor().execute(tool)

assert result.metadata == {
    "category": "test",
    "purpose": "unit-test",
}
```

def test_executor_requires_command_or_executable() -> None:
"""Verify invalid tool configuration is rejected."""
tool = ToolConfiguration(
name="InvalidTool",
timeout_seconds=5,
)

```
with pytest.raises(
    ValueError,
    match="does not define a command or executable",
):
    ToolExecutor().execute(tool)
```

def test_executor_execute_many_runs_all_tools() -> None:
"""Verify multiple tools are executed."""
tools = [
build_python_tool(
"print('first')",
name="ToolOne",
),
build_python_tool(
"print('second')",
name="ToolTwo",
),
]

```
results = ToolExecutor().execute_many(
    tools
)

assert len(results) == 2

assert results[0].tool_name == "ToolOne"
assert results[0].status == ToolExecutionStatus.SUCCESS

assert results[1].tool_name == "ToolTwo"
assert results[1].status == ToolExecutionStatus.SUCCESS
```

def test_executor_execute_many_preserves_order() -> None:
"""Verify batch execution preserves configuration order."""
tools = [
build_python_tool(
"print('one')",
name="First",
),
build_python_tool(
"print('two')",
name="Second",
),
build_python_tool(
"print('three')",
name="Third",
),
]

```
results = ToolExecutor().execute_many(
    tools
)

assert [
    result.tool_name
    for result in results
] == [
    "First",
    "Second",
    "Third",
]
```

def test_executor_execute_many_handles_mixed_results() -> None:
"""Verify batch execution preserves different execution states."""
tools = [
build_python_tool(
"print('success')",
name="SuccessTool",
),
build_python_tool(
"import sys; sys.exit(2)",
name="FailureTool",
),
]

```
results = ToolExecutor().execute_many(
    tools
)

assert results[0].status == ToolExecutionStatus.SUCCESS
assert results[1].status == ToolExecutionStatus.FAILED
```

def test_executor_timeout_result_has_no_exit_code() -> None:
"""Verify timeout execution does not report a normal exit code."""
tool = build_python_tool(
"import time; time.sleep(2)",
timeout_seconds=1,
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.TIMEOUT
assert result.exit_code is None
```

def test_executor_handles_os_error() -> None:
"""Verify unexpected operating-system errors are controlled."""
tool = ToolConfiguration(
name="InvalidOSCommand",
executable="",
command=[
"\0-invalid-command"
],
timeout_seconds=5,
)

```
result = ToolExecutor().execute(tool)

assert result.status == ToolExecutionStatus.FAILED
assert result.failed is True
assert result.error is not None
```

def test_executor_uses_timeout_configuration() -> None:
"""Verify configured timeout is actually enforced."""
tool = build_python_tool(
"import time; time.sleep(0.2)",
timeout_seconds=5,
)

```
start = time.monotonic()

result = ToolExecutor().execute(tool)

elapsed = time.monotonic() - start

assert result.status == ToolExecutionStatus.SUCCESS
assert elapsed < 5
```
