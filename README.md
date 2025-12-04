# @wharfkit/transact-plugin-local-signing

A Wharfkit plugin that enables automatic local signing for specific contract actions. This allows users to approve certain actions once and have them signed automatically without wallet prompts.

## How It Works

1. **On Login**: The plugin prompts the user asking if they want to enable auto-signing for configured actions
2. **If Approved**: A new private key is generated locally and a limited permission is created on-chain via `updateauth` and `linkauth`
3. **On Transact**: Matching actions are automatically signed with the local key - no wallet prompt needed!
4. **On Logout**: The stored keys are automatically cleaned up

The on-chain permission created can **only** perform the specific actions you configure, so even if the local key is compromised, it cannot be used for anything else.

## Installation

```bash
yarn add @wharfkit/transact-plugin-local-signing
# or
npm install @wharfkit/transact-plugin-local-signing
```

## Usage

### Basic Setup

```typescript
import {SessionKit} from '@wharfkit/session'
import {TransactPluginLocalSigning} from '@wharfkit/transact-plugin-local-signing'

// Create the plugin with your configuration
const localSigningPlugin = new TransactPluginLocalSigning({
    actionConfigs: [
        {
            contract: 'gamecontract',
            actions: ['play', 'claim', 'move'],
        },
    ],
})

// Add to SessionKit - note you need BOTH loginPlugins and transactPlugins
const sessionKit = new SessionKit(
    {
        appName: 'myapp',
        chains: [
            /* your chains */
        ],
        ui: myUI,
        walletPlugins: [
            /* your wallet plugins */
        ],
    },
    {
        loginPlugins: [localSigningPlugin.loginPlugin], // For login/logout hooks
        transactPlugins: [localSigningPlugin], // For transaction signing
    }
)
```

### Login Flow

```typescript
// When the user logs in, they'll be prompted:
// "Would you like to enable automatic signing for the following actions on gamecontract?
//  Actions: play, claim, move"
const {session} = await sessionKit.login()

// If they approve, the plugin will:
// 1. Generate a new local key
// 2. Create an updateauth transaction to add a 'local' permission
// 3. Create linkauth transactions to link that permission to the configured actions
// 4. The user signs this setup transaction with their wallet
```

### Transact Flow

```typescript
// After setup, matching actions are signed automatically!
await session.transact({
    action: {
        account: 'gamecontract',
        name: 'play',
        authorization: [{actor: session.actor, permission: 'local'}],
        data: {
            /* ... */
        },
    },
})
// No wallet prompt - signed with local key!

// Non-matching actions still go through the wallet
await session.transact({
    action: {
        account: 'eosio.token',
        name: 'transfer',
        // ...
    },
})
// Normal wallet signing flow
```

### Logout Flow

```typescript
// Keys are automatically cleaned up on logout
await sessionKit.logout(session)
```

## Configuration Options

```typescript
interface TransactPluginLocalSigningOptions {
    // Array of contract/action configurations to handle locally
    actionConfigs: LocalSigningActionConfig[]

    // The permission name to create (default: 'local')
    permissionName?: string
}

interface LocalSigningActionConfig {
    // The contract account name
    contract: string

    // The action names that should be auto-signed
    actions: string[]
}
```

### Example: Multiple Contracts

```typescript
const localSigningPlugin = new TransactPluginLocalSigning({
    actionConfigs: [
        {
            contract: 'gamecontract',
            actions: ['play', 'claim'],
        },
        {
            contract: 'nftcontract',
            actions: ['equip', 'unequip'],
        },
    ],
    permissionName: 'autosign', // Custom permission name
})
```

## API Reference

### TransactPluginLocalSigning

The main plugin class.

| Property       | Type                      | Description                                          |
| -------------- | ------------------------- | ---------------------------------------------------- |
| `id`           | `string`                  | Plugin identifier: `'transact-plugin-local-signing'` |
| `loginPlugin`  | `LocalSigningLoginPlugin` | The login plugin to add to `loginPlugins`            |
| `translations` | `object`                  | Localized UI strings                                 |

| Method                       | Description                                                    |
| ---------------------------- | -------------------------------------------------------------- |
| `isSetup(session, contract)` | Check if local signing is set up for a contract                |
| `isAnySetup(session)`        | Check if local signing is set up for any configured contract   |
| `teardown(session)`          | Manually clean up stored keys (called automatically on logout) |

### LocalSigningLoginPlugin

The companion login plugin (access via `plugin.loginPlugin`).

| Method              | Description                                     |
| ------------------- | ----------------------------------------------- |
| `register(context)` | Registers the `afterLogin` hook                 |
| `onLogout(session)` | Called automatically on logout to clean up keys |

## Security Considerations

-   **Limited Permission**: The created permission can only perform the specific actions you configure
-   **Local Storage**: Private keys are stored in the session storage (typically localStorage)
-   **Session Scoped**: Keys are deleted on logout
-   **User Consent**: Users must explicitly approve enabling auto-signing

## Developing

You need [Make](https://www.gnu.org/software/make/), [node.js](https://nodejs.org/en/) and [yarn](https://classic.yarnpkg.com/en/docs/install) installed.

```bash
# Install dependencies
yarn install

# Build
make lib

# Run tests
make test

# Lint
make check
```

---

Made with ☕️ & ❤️ by [Greymass](https://greymass.com), if you find this useful please consider [supporting us](https://greymass.com/support-us).
