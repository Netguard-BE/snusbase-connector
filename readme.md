# OpenCTI Snusbase

The connector uses the Snusbase API to collect leaked credentials.

## Installation

### Requirements

- OpenCTI Platform >= 6.5.2

### Configuration

| Parameter                            | Docker envvar                | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ |------------------------------| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`              | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`               | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_name`                     | `CONNECTOR_NAME`             | Yes          |                                                                                                                                           |
| `connector_scope`                    | `CONNECTOR_SCOPE`            | Yes          |                                                                                                 |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`        | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `SNUSBASE_API_KEY`                  | `SNUSBASE_API_KEY`          | Yes          | Your Snusbase API KEY                                                                                                                |
| `CONNECTOR_INTERVAL`                 | `CONNECTOR_INTERVAL`            | Yes          | hours to check for leaked credentials                                                                                                                |

### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
