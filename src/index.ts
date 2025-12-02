import {
    AbstractTransactPlugin,
    Action,
    Checksum256,
    Name,
    NameType,
    PrivateKey,
    Signature,
    TransactContext,
    TransactHookResponseType,
    TransactHookTypes,
    Transaction,
} from '@wharfkit/session'

/** Import JSON localization strings */
import defaultTranslations from './translations'

/** Storage key prefix for local signing keys */
const STORAGE_KEY_PREFIX = 'local-signing'

/** The permission name used for local signing */
const DEFAULT_PERMISSION_NAME = 'local'

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
    /** The permission name to create for local signing (default: 'local') */
    permissionName?: NameType
}

/**
 * Data stored for each local signing configuration
 */
interface LocalSigningData {
    /** The private key (WIF format) */
    privateKey: string
    /** The public key */
    publicKey: string
    /** Whether the user has approved local signing */
    approved: boolean
    /** Whether the permission has been set up on chain */
    permissionSetup: boolean
}

export class TransactPluginLocalSigning extends AbstractTransactPlugin {
    /** A unique ID for this plugin */
    id = 'transact-plugin-local-signing'

    /** The translation strings to use for the plugin */
    translations = defaultTranslations

    /** The configured actions to handle locally */
    private actionConfigs: LocalSigningActionConfig[]

    /** The permission name to use for local signing */
    private permissionName: Name

    constructor(options: TransactPluginLocalSigningOptions) {
        super()
        this.actionConfigs = options.actionConfigs.map((config) => ({
            contract: Name.from(config.contract),
            actions: config.actions.map((a) => Name.from(a)),
        }))
        this.permissionName = Name.from(options.permissionName || DEFAULT_PERMISSION_NAME)
    }

    /**
     * Get the storage key for a specific contract
     */
    private getStorageKey(contract: NameType): string {
        return `${STORAGE_KEY_PREFIX}-${contract}-${this.permissionName}`
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
     * Get the contract for a matching action
     */
    private getMatchingContract(action: Action): Name | undefined {
        for (const config of this.actionConfigs) {
            if (
                Name.from(action.account).equals(config.contract) &&
                config.actions.some((a) => Name.from(a).equals(action.name))
            ) {
                return Name.from(config.contract)
            }
        }
        return undefined
    }

    /**
     * Load local signing data from storage
     */
    private async loadLocalSigningData(
        context: TransactContext,
        contract: NameType
    ): Promise<LocalSigningData | undefined> {
        if (!context.storage) {
            return undefined
        }
        const key = this.getStorageKey(contract)
        const data = await context.storage.read(key)
        if (data) {
            return JSON.parse(data) as LocalSigningData
        }
        return undefined
    }

    /**
     * Save local signing data to storage
     */
    private async saveLocalSigningData(
        context: TransactContext,
        contract: NameType,
        data: LocalSigningData
    ): Promise<void> {
        if (!context.storage) {
            throw new Error('Storage is required for local signing')
        }
        const key = this.getStorageKey(contract)
        await context.storage.write(key, JSON.stringify(data))
    }

    /**
     * Generate a new private key for local signing
     */
    private generateLocalKey(): {privateKey: PrivateKey; publicKey: string} {
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
     */
    private createUpdateAuthAction(
        account: NameType,
        publicKey: string,
        parentPermission: NameType = 'active'
    ): Action {
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
                permission: this.permissionName,
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
     */
    private createLinkAuthActions(
        account: NameType,
        contract: NameType,
        actions: NameType[]
    ): Action[] {
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
                    requirement: this.permissionName,
                },
            })
        )
    }

    /**
     * Register the hooks required for this plugin to function
     */
    register(context: TransactContext): void {
        // Get the translation function from the UI if it exists
        const t = context.ui?.getTranslate(this.id)

        // Register the beforeSign hook
        context.addHook(
            TransactHookTypes.beforeSign,
            async (request, context): Promise<TransactHookResponseType> => {
                // Resolve the request to get the transaction
                const resolved = await context.resolve(request)
                const transaction = Transaction.from(resolved.transaction)

                // Check if any action should be handled by local signing
                const matchingActions = transaction.actions.filter((action) =>
                    this.isLocalSigningAction(action)
                )

                if (matchingActions.length === 0) {
                    // No matching actions, let the transaction proceed normally
                    return
                }

                // Get the first matching contract (for simplicity, handle one at a time)
                const contract = this.getMatchingContract(matchingActions[0])
                if (!contract) {
                    return
                }

                // Load existing local signing data
                let localData = await this.loadLocalSigningData(context, contract)

                // If no local data exists, prompt the user for approval
                if (!localData || !localData.approved) {
                    if (!context.ui) {
                        // No UI available, cannot prompt user
                        return
                    }

                    // Find the config for this contract to get the action names
                    const config = this.actionConfigs.find((c) =>
                        Name.from(c.contract).equals(contract)
                    )
                    if (!config) {
                        return
                    }

                    const actionNames = config.actions.map((a) => String(a)).join(', ')

                    // Prompt the user
                    const promptResponse = await context.ui.prompt({
                        title: t
                            ? t('prompt.title', {default: 'Enable Auto-Signing?'})
                            : 'Enable Auto-Signing?',
                        body: t
                            ? t('prompt.body', {
                                  default: `Would you like to enable automatic signing for the following actions on ${contract}?\n\nActions: ${actionNames}\n\nThis will create a new permission on your account that can only perform these specific actions.`,
                                  contract: String(contract),
                                  actions: actionNames,
                              })
                            : `Would you like to enable automatic signing for the following actions on ${contract}?\n\nActions: ${actionNames}\n\nThis will create a new permission on your account that can only perform these specific actions.`,
                        elements: [
                            {
                                type: 'button',
                                label: t
                                    ? t('prompt.enable', {default: 'Enable Auto-Signing'})
                                    : 'Enable Auto-Signing',
                                data: {
                                    onClick: () => ({approved: true}),
                                    label: t
                                        ? t('prompt.enable', {default: 'Enable Auto-Signing'})
                                        : 'Enable Auto-Signing',
                                    variant: 'primary',
                                },
                            },
                            {
                                type: 'button',
                                label: t
                                    ? t('prompt.skip', {default: 'Sign Manually This Time'})
                                    : 'Sign Manually This Time',
                                data: {
                                    onClick: () => ({approved: false}),
                                    label: t
                                        ? t('prompt.skip', {default: 'Sign Manually This Time'})
                                        : 'Sign Manually This Time',
                                },
                            },
                        ],
                    })

                    // Check if user approved
                    if (!promptResponse || !(promptResponse as {approved?: boolean}).approved) {
                        // User declined, proceed with normal signing
                        return
                    }

                    // Generate a new key pair
                    const {privateKey, publicKey} = this.generateLocalKey()

                    // Save the local signing data
                    localData = {
                        privateKey: String(privateKey),
                        publicKey,
                        approved: true,
                        permissionSetup: false,
                    }
                    await this.saveLocalSigningData(context, contract, localData)

                    // Create the permission setup actions
                    const updateAuthAction = this.createUpdateAuthAction(
                        context.accountName,
                        publicKey
                    )
                    const linkAuthActions = this.createLinkAuthActions(
                        context.accountName,
                        contract,
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

                    // Update the stored data to indicate permission is being set up
                    localData.permissionSetup = true
                    await this.saveLocalSigningData(context, contract, localData)

                    // Return the modified request - user will sign with their wallet
                    return {
                        request: newRequest,
                    }
                }

                // If permission is set up, sign locally
                if (localData.permissionSetup && localData.privateKey) {
                    // Check if ALL actions in the transaction are local signing actions
                    const allActionsAreLocal = transaction.actions.every((action) =>
                        this.isLocalSigningAction(action)
                    )

                    if (allActionsAreLocal) {
                        // Sign with the local key
                        const signature = this.signWithLocalKey(
                            transaction,
                            Checksum256.from(context.chain.id),
                            localData.privateKey
                        )

                        // Show a brief notification if UI is available
                        if (context.ui) {
                            context.ui.prompt({
                                title: t
                                    ? t('signed.title', {default: 'Auto-Signed'})
                                    : 'Auto-Signed',
                                body: t
                                    ? t('signed.body', {
                                          default:
                                              'Transaction was automatically signed with your local key.',
                                      })
                                    : 'Transaction was automatically signed with your local key.',
                                elements: [],
                            })
                        }

                        // Return the signatures
                        return {
                            request,
                            signatures: [signature],
                        }
                    }
                }

                // If we get here, let the transaction proceed normally
                return
            }
        )
    }
}
