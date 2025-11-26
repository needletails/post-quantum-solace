# ``SessionContext``

A model representing the complete session state and configuration.

## Overview

`SessionContext` contains all the information needed to restore and maintain a session, including user information, cryptographic keys, and session state.

## Topics

### Essentials

- ``SessionContext/sessionUser``
- ``SessionContext/databaseEncryptionKey``
- ``SessionContext/activeUserConfiguration``

### Registration

- ``SessionContext/RegistrationState``

## Key Features

- **Complete State**: Contains all session information
- **Encrypted Storage**: Stored encrypted in the session cache
- **Restoration**: Can be used to restore session state

## See Also

- ``SessionUser``
- ``UserConfiguration``
- ``SessionCache``
