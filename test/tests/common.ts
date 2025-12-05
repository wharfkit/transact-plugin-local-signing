import {assert} from 'chai'

import {
    LocalSigningLoginPlugin,
    TransactPluginLocalSigning,
    TransactPluginLocalSigningOptions,
} from '../../src/index'

import {Name, PrivateKey, Session, SessionArgs, SessionOptions} from '@wharfkit/session'
import {mockFetch, MockStorage} from '@wharfkit/mock-data'
import {WalletPluginPrivateKey} from '@wharfkit/wallet-plugin-privatekey'

const wallet = new WalletPluginPrivateKey('5Jtoxgny5tT7NiNFp1MLogviuPJ9NniWjnU4wKzaX4t7pL4kJ8s')

const mockSessionArgs: SessionArgs = {
    chain: {
        id: '73e4385a2708e6d7048834fbc1079f2fabb17b3c125b146af438971e90716c4d',
        url: 'https://jungle4.greymass.com',
    },
    permissionLevel: 'wharfkit1131@test',
    walletPlugin: wallet,
}

suite('TransactPluginLocalSigning', function () {
    suite('constructor', function () {
        test('should create plugin with valid config', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'eosio.token',
                        actions: ['transfer'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)
            assert.equal(plugin.id, 'transact-plugin-local-signing')
        })

        test('should create plugin with multiple action configs', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'eosio.token',
                        actions: ['transfer', 'issue'],
                    },
                    {
                        contract: 'gamecontract',
                        actions: ['play', 'claim'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)
            assert.equal(plugin.id, 'transact-plugin-local-signing')
        })

        test('should create a loginPlugin', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)
            assert.isDefined(plugin.loginPlugin)
            assert.instanceOf(plugin.loginPlugin, LocalSigningLoginPlugin)
        })
    })

    suite('action matching', function () {
        test('should not interfere with non-matching actions', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const mockSessionOptions: SessionOptions = {
                fetch: mockFetch,
                storage,
                transactPlugins: [plugin],
            }

            const session = new Session(mockSessionArgs, mockSessionOptions)

            // This action doesn't match the configured actions
            const action = {
                authorization: [
                    {
                        actor: 'wharfkit1115',
                        permission: 'test',
                    },
                ],
                account: 'eosio.token',
                name: 'transfer',
                data: {
                    from: 'wharfkit1115',
                    to: 'wharfkittest',
                    quantity: '0.0001 EOS',
                    memo: 'test',
                },
            }

            // Should proceed normally without any local signing interaction
            const result = await session.transact({action}, {broadcast: false})
            assert.isArray(result.signatures)
            assert.lengthOf(result.signatures, 1)
        })
    })

    suite('key generation', function () {
        test('should generate valid K1 key pairs', function () {
            const privateKey = PrivateKey.generate('K1')
            const publicKey = privateKey.toPublic()

            assert.isTrue(String(privateKey).startsWith('PVT_K1_'))
            assert.isTrue(String(publicKey).startsWith('PUB_K1_'))
        })

        test('generateLocalKey should return valid key pair', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)
            const {privateKey, publicKey} = plugin.generateLocalKey()

            assert.isTrue(String(privateKey).startsWith('PVT_K1_'))
            assert.isTrue(publicKey.startsWith('PUB_K1_'))
        })
    })

    suite('storage operations', function () {
        test('should save and load private key (obfuscated)', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const testKey = 'PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V'

            await plugin.savePrivateKey(storage, 'gamecontract', testKey)
            const loaded = await plugin.loadPrivateKey(storage, 'gamecontract')

            assert.equal(loaded, testKey)
        })

        test('should store key obfuscated (not raw WIF)', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const testKey = 'PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V'

            await plugin.savePrivateKey(storage, 'gamecontract', testKey)

            // Read raw storage value
            const storageKey = plugin.getStorageKey('gamecontract')
            const rawValue = await storage.read(storageKey)

            // Should NOT contain the raw WIF prefix patterns
            assert.isFalse(rawValue?.startsWith('PVT_K1_'))
            assert.isFalse(rawValue?.startsWith('5J'))
            assert.isFalse(rawValue?.startsWith('5K'))
            assert.isFalse(rawValue?.startsWith('5H'))
        })

        test('should delete private key', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const testKey = 'PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V'

            await plugin.savePrivateKey(storage, 'gamecontract', testKey)
            await plugin.deletePrivateKey(storage, 'gamecontract')
            const loaded = await plugin.loadPrivateKey(storage, 'gamecontract')

            assert.isUndefined(loaded)
        })

        test('should return undefined for non-existent key', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const loaded = await plugin.loadPrivateKey(storage, 'nonexistent')
            assert.isUndefined(loaded)
        })
    })

    suite('isSetup', function () {
        test('should return false when no key exists', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const mockSessionOptions: SessionOptions = {
                fetch: mockFetch,
                storage,
                transactPlugins: [plugin],
            }
            const session = new Session(mockSessionArgs, mockSessionOptions)

            const result = await plugin.isSetup(session, 'gamecontract')
            assert.isFalse(result)
        })

        test('should return true when key exists (key exists = permission set up)', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const mockSessionOptions: SessionOptions = {
                fetch: mockFetch,
                storage,
                transactPlugins: [plugin],
            }
            const session = new Session(mockSessionArgs, mockSessionOptions)

            // Save a key
            await plugin.savePrivateKey(
                storage,
                'gamecontract',
                'PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V'
            )

            const result = await plugin.isSetup(session, 'gamecontract')
            assert.isTrue(result)
        })
    })

    suite('teardown', function () {
        test('should delete all stored keys', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                    {
                        contract: 'othercontrc', // EOSIO names max 12 chars
                        actions: ['action1'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const mockSessionOptions: SessionOptions = {
                fetch: mockFetch,
                storage,
                transactPlugins: [plugin],
            }
            const session = new Session(mockSessionArgs, mockSessionOptions)

            // Save keys for both contracts
            await plugin.savePrivateKey(
                storage,
                'gamecontract',
                'PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V'
            )
            await plugin.savePrivateKey(
                storage,
                'othercontrc',
                'PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V'
            )

            // Verify keys exist
            assert.isDefined(await plugin.loadPrivateKey(storage, 'gamecontract'))
            assert.isDefined(await plugin.loadPrivateKey(storage, 'othercontrc'))

            // Call teardown
            await plugin.teardown(session)

            // Verify keys are deleted
            assert.isUndefined(await plugin.loadPrivateKey(storage, 'gamecontract'))
            assert.isUndefined(await plugin.loadPrivateKey(storage, 'othercontrc'))
        })
    })

    suite('Name handling', function () {
        test('should correctly compare Name objects', function () {
            const name1 = Name.from('testaccount')
            const name2 = Name.from('testaccount')
            const name3 = Name.from('otheraccount')

            assert.isTrue(name1.equals(name2))
            assert.isFalse(name1.equals(name3))
        })

        test('should correctly handle action names', function () {
            const actions = ['transfer', 'issue', 'play'].map((a) => Name.from(a))
            const targetAction = Name.from('transfer')

            const found = actions.some((a) => a.equals(targetAction))
            assert.isTrue(found)
        })
    })

    suite('getters', function () {
        test('getStorageKey should return shipload-style key format', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const key = plugin.getStorageKey('gamecontract')
            assert.equal(key, 'localsession-gamecontract')
        })

        test('getActionConfigs should return configured actions', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play', 'claim'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            const configs = plugin.getActionConfigs()
            assert.lengthOf(configs, 1)
            assert.isTrue(Name.from(configs[0].contract).equals(Name.from('gamecontract')))
            assert.lengthOf(configs[0].actions, 2)
        })

        test('getPermissionName should return contract name as permission', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            // Permission name = contract name (shipload pattern)
            const permName = plugin.getPermissionName('gamecontract')
            assert.isTrue(permName.equals(Name.from('gamecontract')))
        })
    })

    suite('translations', function () {
        test('should have translations defined', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'eosio.token',
                        actions: ['transfer'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)
            assert.isDefined(plugin.translations)
            assert.isDefined(plugin.translations.en)
        })
    })

    suite('obfuscation', function () {
        test('should round-trip obfuscation correctly', async function () {
            const storage = new MockStorage()
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'gamecontract',
                        actions: ['play'],
                    },
                ],
            }
            const plugin = new TransactPluginLocalSigning(options)

            // Test with various key formats
            const testKeys = [
                'PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V',
                '5JuH9fCXmU3xbj8nRmhPZaVrxxXrdPaRaPhAbW4DU1RCNKY2gDq',
                '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3',
            ]

            for (const testKey of testKeys) {
                await plugin.savePrivateKey(storage, 'gamecontract', testKey)
                const loaded = await plugin.loadPrivateKey(storage, 'gamecontract')
                assert.equal(
                    loaded,
                    testKey,
                    `Failed to round-trip key: ${testKey.substring(0, 10)}...`
                )
            }
        })
    })
})
