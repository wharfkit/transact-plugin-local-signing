import {
    AbstractLoginPlugin,
    AbstractTransactPlugin,
    Action,
    Checksum256,
    LoginContext,
    LoginHookTypes,
    Name,
    NameType,
    PrivateKey,
    Session,
    SessionStorage,
    Signature,
    TransactContext,
    TransactHookResponseType,
    TransactHookTypes,
    Transaction,
} from '@wharfkit/session'

/** Import JSON localization strings */
import defaultTranslations from './translations'

/** Storage key prefix for local signing keys (matches shipload pattern) */
const STORAGE_KEY_PREFIX = 'localsession'

/**
 * Configuration for actions that should be handled by local signing
 */
export interface LocalSigningActionConfig {
    /** The contract account name */
    contract: NameType
    /** The action names that should be auto-signed */
    actions: NameType[]
}

/**
 * Options for the TransactPluginLocalSigning plugin
 */
export interface TransactPluginLocalSigningOptions {
    /** Array of contract/action configurations to handle locally */
    actionConfigs: LocalSigningActionConfig[]
}

/**
 * Data stored for each local signing configuration
 */
interface LocalSigningData {
    /** The private key (WIF format) */
    privateKey: string
    /** The public key */
    publicKey: string
    /** Whether the permission has been set up on chain */
    permissionSetup: boolean
}

/**
 * A plugin that enables automatic local signing for specific contract actions.
 *
 * Usage:
 * ```typescript
 * const localSigningPlugin = new TransactPluginLocalSigning({
 *     actionConfigs: [
 *         { contract: 'gamecontract', actions: ['play', 'claim'] }
 *     ]
 * })
 *
 * // The permission name will be the contract name itself (e.g., 'gamecontract')
 * // This follows the shipload pattern for local session keys
 *
 * const sessionKit = new SessionKit({
 *     // ...
 * }, {
 *     loginPlugins: [localSigningPlugin.loginPlugin],
 *     transactPlugins: [localSigningPlugin],
 * })
 *
 * // Login - prompts user and sets up permissions
 * const { session } = await sessionKit.login()
 *
 * // Transact - auto-signed with local key!
 * await session.transact({ action: playAction })
 *
 * // Logout - automatically cleans up keys via onLogout
 * await sessionKit.logout(session)
 * ```
 */
export class TransactPluginLocalSigning extends AbstractTransactPlugin {
    /** A unique ID for this plugin */
    id = 'transact-plugin-local-signing'

    /** The translation strings to use for the plugin */
    translations = defaultTranslations

    /** The configured actions to handle locally */
    private actionConfigs: LocalSigningActionConfig[]

    /** The login plugin instance - add this to loginPlugins array */
    public readonly loginPlugin: LocalSigningLoginPlugin

    constructor(options: TransactPluginLocalSigningOptions) {
        super()
        this.actionConfigs = options.actionConfigs.map((config) => ({
            contract: Name.from(config.contract),
            actions: config.actions.map((a) => Name.from(a)),
        }))

        // Create the companion login plugin
        this.loginPlugin = new LocalSigningLoginPlugin(this)
    }

    /**
     * Get the storage key for a specific contract (matches shipload pattern)
     */
    getStorageKey(contract: NameType): string {
        return `${STORAGE_KEY_PREFIX}-${contract}`
    }

    /**
     * Get the configured action configs
     */
    getActionConfigs(): LocalSigningActionConfig[] {
        return this.actionConfigs
    }

    /**
     * Get the permission name for a contract (permission name = contract name)
     * This follows the shipload pattern where the permission is named after the contract.
     */
    getPermissionName(contract: NameType): Name {
        return Name.from(contract)
    }

    /**
     * Check if an action should be handled by local signing
     */
    private isLocalSigningAction(action: Action): boolean {
        for (const config of this.actionConfigs) {
            if (
                Name.from(action.account).equals(config.contract) &&
                config.actions.some((a) => Name.from(a).equals(action.name))
            ) {
                return true
            }
        }
        return false
    }

    /**
     * Load local signing data from storage
     */
    async loadLocalSigningData(
        storage: SessionStorage,
        contract: NameType
    ): Promise<LocalSigningData | undefined> {
        const key = this.getStorageKey(contract)
        const data = await storage.read(key)
        if (data) {
            return JSON.parse(data) as LocalSigningData
        }
        return undefined
    }

    /**
     * Save local signing data to storage
     */
    async saveLocalSigningData(
        storage: SessionStorage,
        contract: NameType,
        data: LocalSigningData
    ): Promise<void> {
        const key = this.getStorageKey(contract)
        await storage.write(key, JSON.stringify(data))
    }

    /**
     * Delete local signing data from storage
     */
    async deleteLocalSigningData(storage: SessionStorage, contract: NameType): Promise<void> {
        const key = this.getStorageKey(contract)
        await storage.remove(key)
    }

    /**
     * Generate a new private key for local signing
     */
    generateLocalKey(): {privateKey: PrivateKey; publicKey: string} {
        const privateKey = PrivateKey.generate('K1')
        const publicKey = String(privateKey.toPublic())
        return {privateKey, publicKey}
    }

    /**
     * Sign a transaction with the local private key
     */
    private signWithLocalKey(
        transaction: Transaction,
        chainId: Checksum256,
        privateKeyWif: string
    ): Signature {
        const privateKey = PrivateKey.from(privateKeyWif)
        const digest = transaction.signingDigest(chainId)
        return privateKey.signDigest(digest)
    }

    /**
     * Create the updateauth action to add a new permission
     * Permission name = contract name (following shipload pattern)
     */
    createUpdateAuthAction(
        account: NameType,
        contract: NameType,
        publicKey: string,
        parentPermission: NameType = 'active'
    ): Action {
        const permissionName = this.getPermissionName(contract)
        return Action.from({
            account: 'eosio',
            name: 'updateauth',
            authorization: [
                {
                    actor: account,
                    permission: parentPermission,
                },
            ],
            data: {
                account: account,
                permission: permissionName,
                parent: parentPermission,
                auth: {
                    threshold: 1,
                    keys: [
                        {
                            key: publicKey,
                            weight: 1,
                        },
                    ],
                    accounts: [],
                    waits: [],
                },
            },
        })
    }

    /**
     * Create the linkauth action to link the permission to specific actions
     * Permission name = contract name (following shipload pattern)
     */
    createLinkAuthActions(account: NameType, contract: NameType, actions: NameType[]): Action[] {
        const permissionName = this.getPermissionName(contract)
        return actions.map((actionName) =>
            Action.from({
                account: 'eosio',
                name: 'linkauth',
                authorization: [
                    {
                        actor: account,
                        permission: 'active',
                    },
                ],
                data: {
                    account: account,
                    code: contract,
                    type: actionName,
                    requirement: permissionName,
                },
            })
        )
    }

    /**
     * Check if local signing is already set up for a contract
     */
    async isSetup(session: Session, contract: NameType): Promise<boolean> {
        if (!session.storage) {
            return false
        }
        const data = await this.loadLocalSigningData(session.storage, contract)
        return data?.permissionSetup === true
    }

    /**
     * Check if local signing is set up for any configured contract
     */
    async isAnySetup(session: Session): Promise<boolean> {
        for (const config of this.actionConfigs) {
            if (await this.isSetup(session, config.contract)) {
                return true
            }
        }
        return false
    }

    /**
     * Teardown local signing - deletes stored private keys
     *
     * Called automatically via onLogout when using updated SessionKit.
     * The on-chain permissions remain but won't be usable without the keys.
     *
     * @param session The session to tear down local signing for
     */
    async teardown(session: Session): Promise<void> {
        if (!session.storage) {
            return
        }

        // Delete stored keys for all configured contracts
        for (const config of this.actionConfigs) {
            await this.deleteLocalSigningData(session.storage, config.contract)
        }
    }

    /**
     * Register the transact hooks for local signing
     */
    register(context: TransactContext): void {
        context.addHook(
            TransactHookTypes.beforeSign,
            async (request, context): Promise<TransactHookResponseType> => {
                if (!context.storage) {
                    return // No storage, can't use local signing
                }

                // Resolve the request to get the transaction
                const resolved = await context.resolve(request)
                const transaction = Transaction.from(resolved.transaction)

                // Check if any actions need local signing setup
                for (const config of this.actionConfigs) {
                    const localData = await this.loadLocalSigningData(
                        context.storage,
                        config.contract
                    )

                    // If we have key data but permission isn't set up yet, prepend the setup actions
                    if (localData && !localData.permissionSetup) {
                        const updateAuthAction = this.createUpdateAuthAction(
                            context.accountName,
                            config.contract,
                            localData.publicKey
                        )
                        const linkAuthActions = this.createLinkAuthActions(
                            context.accountName,
                            config.contract,
                            config.actions
                        )

                        // Create a new request with the permission setup actions prepended
                        const allActions = [
                            updateAuthAction,
                            ...linkAuthActions,
                            ...transaction.actions,
                        ]
                        const newRequest = await context.createRequest({
                            actions: allActions,
                        })

                        // Mark as set up (optimistically - if tx fails, user can retry)
                        localData.permissionSetup = true
                        await this.saveLocalSigningData(context.storage, config.contract, localData)

                        // Return the modified request - user will sign with their wallet
                        return {
                            request: newRequest,
                        }
                    }
                }

                // Check if ALL actions in the transaction can be handled by local signing
                const allActionsAreLocal = transaction.actions.every((action) =>
                    this.isLocalSigningAction(action)
                )

                if (!allActionsAreLocal) {
                    // Some actions aren't configured for local signing, proceed normally
                    return
                }

                // Find the first matching contract to get the stored key
                let localData: LocalSigningData | undefined
                for (const action of transaction.actions) {
                    for (const config of this.actionConfigs) {
                        if (Name.from(action.account).equals(config.contract)) {
                            localData = await this.loadLocalSigningData(
                                context.storage,
                                config.contract
                            )
                            if (localData?.permissionSetup) {
                                break
                            }
                        }
                    }
                    if (localData?.permissionSetup) {
                        break
                    }
                }

                if (!localData?.permissionSetup || !localData.privateKey) {
                    // Not set up yet, proceed with normal signing
                    return
                }

                // Sign with the local key
                const signature = this.signWithLocalKey(
                    transaction,
                    Checksum256.from(context.chain.id),
                    localData.privateKey
                )

                // Return the signatures
                return {
                    request,
                    signatures: [signature],
                }
            }
        )
    }
}

/**
 * Companion LoginPlugin for TransactPluginLocalSigning
 *
 * Handles prompting the user during login and cleanup on logout.
 * Access via `plugin.loginPlugin` and add to `loginPlugins` array.
 */
export class LocalSigningLoginPlugin extends AbstractLoginPlugin {
    private parent: TransactPluginLocalSigning

    constructor(parent: TransactPluginLocalSigning) {
        super()
        this.parent = parent
    }

    /**
     * Called when a session is logged out.
     * Cleans up stored local signing keys.
     */
    async onLogout(session: Session): Promise<void> {
        await this.parent.teardown(session)
    }

    /**
     * Register login hooks - prompts user to enable local signing after login
     */
    register(context: LoginContext): void {
        context.addHook(LoginHookTypes.afterLogin, async (ctx: LoginContext) => {
            // Get storage from session if available (requires updated SessionKit),
            // otherwise fall back to browser storage
            const ctxWithSession = ctx as LoginContext & {session?: Session}
            const storage = ctxWithSession.session?.storage || this.getBrowserStorage()
            if (!storage) {
                return
            }

            const t = ctx.ui.getTranslate(this.parent.id)

            // Process each configured contract
            for (const config of this.parent.getActionConfigs()) {
                // Check if already set up
                const existingData = await this.parent.loadLocalSigningData(
                    storage,
                    config.contract
                )
                if (existingData?.privateKey) {
                    continue // Already have a key for this contract
                }

                const actionNames = config.actions.map((a) => String(a)).join(', ')

                // Prompt the user
                try {
                    const promptResponse = await ctx.ui.prompt({
                        title: t('prompt.title', {default: 'Enable Auto-Signing?'}),
                        body: t('prompt.body', {
                            default: `Would you like to enable automatic signing for the following actions on ${config.contract}?\n\nActions: ${actionNames}\n\nThis will create a new permission on your account that can only perform these specific actions.`,
                            contract: String(config.contract),
                            actions: actionNames,
                        }),
                        elements: [
                            {
                                type: 'button',
                                label: t('prompt.enable', {default: 'Enable Auto-Signing'}),
                                data: {
                                    onClick: () => ({approved: true}),
                                    label: t('prompt.enable', {default: 'Enable Auto-Signing'}),
                                    variant: 'primary',
                                },
                            },
                            {
                                type: 'button',
                                label: t('prompt.skip', {default: 'No Thanks'}),
                                data: {
                                    onClick: () => ({approved: false}),
                                    label: t('prompt.skip', {default: 'No Thanks'}),
                                },
                            },
                        ],
                    })

                    // Check if user approved
                    if (!promptResponse || !(promptResponse as {approved?: boolean}).approved) {
                        continue // User declined for this contract
                    }
                } catch {
                    // User closed the prompt
                    continue
                }

                // Generate a new key pair
                const {privateKey, publicKey} = this.parent.generateLocalKey()

                // Save the local signing data
                const localData: LocalSigningData = {
                    privateKey: String(privateKey),
                    publicKey,
                    permissionSetup: false,
                }
                await this.parent.saveLocalSigningData(storage, config.contract, localData)

                // If we have access to the session, set up the permission now
                if (ctxWithSession.session) {
                    try {
                        const updateAuthAction = this.parent.createUpdateAuthAction(
                            ctxWithSession.session.actor,
                            config.contract,
                            publicKey
                        )
                        const linkAuthActions = this.parent.createLinkAuthActions(
                            ctxWithSession.session.actor,
                            config.contract,
                            config.actions
                        )

                        // Execute the permission setup transaction
                        await ctxWithSession.session.transact({
                            actions: [updateAuthAction, ...linkAuthActions],
                        })

                        // Mark as set up
                        localData.permissionSetup = true
                        await this.parent.saveLocalSigningData(storage, config.contract, localData)
                    } catch (error) {
                        // Transaction failed, clean up the stored data
                        await this.parent.deleteLocalSigningData(storage, config.contract)
                        throw error
                    }
                }
                // If no session available (old SessionKit), permission setup happens on first transact
            }
        })
    }

    /**
     * Fallback storage using browser localStorage (for backwards compatibility)
     */
    private getBrowserStorage(): SessionStorage | undefined {
        if (typeof window !== 'undefined' && window.localStorage) {
            return {
                write: async (key: string, data: string) => {
                    window.localStorage.setItem(key, data)
                },
                read: async (key: string): Promise<string | null> => {
                    return window.localStorage.getItem(key)
                },
                remove: async (key: string) => {
                    window.localStorage.removeItem(key)
                },
            }
        }
        return undefined
    }
}
