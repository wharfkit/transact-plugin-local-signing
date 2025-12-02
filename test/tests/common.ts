import {assert} from 'chai'

import {TransactPluginLocalSigning, TransactPluginLocalSigningOptions} from '../../src/index'

import {Name, PrivateKey, Session, SessionArgs, SessionOptions} from '@wharfkit/session'
import {mockFetch, MockStorage} from '@wharfkit/mock-data'
import {WalletPluginPrivateKey} from '@wharfkit/wallet-plugin-privatekey'

const wallet = new WalletPluginPrivateKey(
    '5Jtoxgny5tT7NiNFp1MLogviuPJ9NniWjnU4wKzaX4t7pL4kJ8s'
)

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

        test('should accept custom permission name', function () {
            const options: TransactPluginLocalSigningOptions = {
                actionConfigs: [
                    {
                        contract: 'eosio.token',
                        actions: ['transfer'],
                    },
                ],
                permissionName: 'autosign',
            }
            const plugin = new TransactPluginLocalSigning(options)
            assert.equal(plugin.id, 'transact-plugin-local-signing')
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
})
