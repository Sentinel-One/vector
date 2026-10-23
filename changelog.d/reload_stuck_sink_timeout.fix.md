Config reloads no longer hang forever when a changed sink that reuses its buffer stops polling its input. Vector now waits up to 120 seconds for the old sink to finish (or forever with `--no-graceful-shutdown-limit`), then drops it, along with any events it had already taken from its buffer, and starts the new sink on the same buffer. Previously the reload waited forever and the process stopped applying config changes. Ported from upstream vectordotdev/vector#26688.

authors: JuanMantica45
