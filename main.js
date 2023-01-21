const { Wallet, initKaspaFramework } = require('@kaspa/wallet');
const { RPC } = require('@kaspa/grpc-node');
const express = require('express')
const Keyv = require("keyv")
const crypto = require('crypto')
const validator = require('validator')
const uuid4 = require('uuid4')

const network = "kaspa";
const rpc = new RPC({ clientConfig: { host: process.env.KASPAD_ADDR } });
const userStore = new Keyv(process.env.DB_ADDR, { serialize: JSON.stringify, deserialize: JSON.parse });
const app = express()

app.use(express.json());

// minimum required password
const checkPassword = (pw) => {
    return (pw.length >= 8)
}

// api-docs route for some testing and documentation
const swaggerUi = require('swagger-ui-express');
const swaggerDocument = require('./swagger.json');
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));
app.use(/^\/$/i, (req, res) => {
    res.redirect(301, '/api-docs');
});

// get wallet info for uuid
app.get('/wallets/:wId', (req, res) => {
    userStore.get(req.params.wId).then(async (walletInfo) => {
        if (!!walletInfo) {
            const publicAddress = walletInfo.publicAddress
            const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
            const [basicUser, basicPassword] = Buffer.from(b64auth, 'base64').toString().split(':')

            if (!basicPassword) {
                // simple info, if no PW given
                res.json({
                    publicAddress
                })
                return
            } else {
                // password given - decrypt wallet
                if (crypto.createHash('sha256').update(basicPassword).digest('hex') == walletInfo.hashPassword) {
                    // pw is fine. Decode wallet
                    const wallet = await Wallet.import(basicPassword, walletInfo.encryptedMnemonic, { network, rpc }, { disableAddressDerivation: true })
                    // return extended information
                    res.json({
                        "publicAddress": publicAddress,
                        "uuid": walletInfo.uuid,
                        "encryptedMnemonic": walletInfo.encryptedMnemonic,
                        "mnemonic": wallet.mnemonic
                    })
                    return

                } else {
                    res.status(403).send('Password incorrect.')
                    return
                }
            }
        } else {
            res.status(404).send('Wallet not found')
        }
    }
    )
})

// endpoint: create a new wallet
app.post('/wallets', (req, res) => {
    // password needed for wallet creation
    if (!req.body.password) {
        res.status(400).send('Password needed.')
        return
    }

    // check if password matches rules
    if (checkPassword(req.body.password) === false) {
        res.status(400).send('Password needs to have at least 8 chars.')
        return
    }

    // either use given uuid or random uuid
    const uuid = req.body.uuid || uuid4()

    // check if given uuid is correct format
    if (!validator.isUUID(uuid)) {
        res.status(400).send("invalid UUID")
        return
    }

    // check if uuid is free -> create wallet
    userStore.get(uuid).then(async (data) => {
        // uuid already set? return 400
        if (data !== undefined) {
            res.status(400).send('Uuid already set.')
            return
        } else {
            // create a new wallet

            // save hash of password for future verification
            const hashPassword = crypto.createHash('sha256').update(req.body.password).digest('hex')

            // create a wallet, disable address derivation => one static kaspa address
            const wallet = new Wallet(null, null, { network, rpc }, { disableAddressDerivation: true })

            const publicAddress = wallet.receiveAddress
            const encryptedMnemonic = await wallet.export(req.body.password)

            // first set password to userStore and then return the data
            userStore.set(uuid, {
                publicAddress,
                encryptedMnemonic,
                hashPassword
            }).then(() => res.json({
                "publicAddress": publicAddress,
                "uuid": uuid,
                encryptedMnemonic,
                "mnemonic": wallet.mnemonic
            }))
                .catch(() => res.status(400).send('Error saving wallet.'))
        }
    })
})

app.put('/wallets/:wId', (req, res) => {
    userStore.get(req.params.wId).then(async (data) => {
        if (data === undefined) {
            res.status(404).send('Wallet not found.')
            return
        } else {
            const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
            const [basicUser, basicPassword] = Buffer.from(b64auth, 'base64').toString().split(':')

            if (crypto.createHash('sha256').update(basicPassword).digest('hex') == data.hashPassword) {
                if (!!req.body.password) {

                    if (checkPassword(req.body.password) === false) {
                        res.status(400).send('Password needs to have at least 8 chars.')
                        return
                    }

                    const wallet = await Wallet.import(basicPassword, data.encryptedMnemonic, { network, rpc }, { disableAddressDerivation: true })
                    const encryptedMnemonic = await wallet.export(req.body.password)

                    // update data object
                    data.encryptedMnemonic = encryptedMnemonic
                    data.hashPassword = crypto.createHash('sha256').update(req.body.password).digest('hex')

                    // update database
                    userStore.set(req.params.wId, data).then(() =>
                        // return new object
                        res.json({
                            publicAddress: data.publicAddress,
                            encryptedMnemonic: data.encryptedMnemonic,
                            mnemonic: wallet.mnemonic
                        }))
                        .catch(() => res.status(400).send('Error saving wallet.'))

                    return
                }

            } else {
                res.status(403).send('Password incorrect.')
                return
            }
        }
    }).catch(() => res.status(400).send('Error reading wallet.'))
})

app.post('/wallets/:wId/transactions', (req, res) => {
    userStore.get(req.params.wId).then(async (data) => {
        if (data === undefined) {
            res.status(404).send('Wallet not found.')
            return
        } else {
            if (!req.header.authorization) {
                res.status(400).send("Auth Basic password needed.")
                return
            }
            // parse login and password from headers
            const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
            const [basicUser, basicPassword] = Buffer.from(b64auth, 'base64').toString().split(':')

            if (crypto.createHash('sha256').update(basicPassword).digest('hex') == data.hashPassword) {
                // pw is fine. Decode wallet

                if (!req.body.toAddr) {
                    res.status(400).send("toAddr parameter needed"); return
                }

                if (!req.body.amount) {
                    res.status(400).send("amount parameter needed"); return
                }

                const wallet = await Wallet.import(basicPassword, data.encryptedMnemonic, { network, rpc }, { disableAddressDerivation: true })
                await wallet.submitTransaction({
                    toAddr: req.body.toAddr,
                    amount: req.body.amount,
                    changeAddrOverride: wallet.receiveAddress,
                    calculateNetworkFee: true,
                    inclusiveFee: req.body.inclusiveFee ? true : false
                }, true)
                    .then((e) => res.send(`${e.txid}`))
                    .catch((e) => {
                        if (JSON.stringify(e) !== "{}") {
                            res.status(400).send(`${JSON.stringify(e)}`)
                            return
                        } else {
                            res.status(400).send(`${e}`)
                            return
                        }
                    })
            } else {
                res.status(403).send('Password incorrect.')
                return
            }
        }
    }).catch(() => res.status(400).send('Error reading wallet.'))
})

// init wallet
const init = async () => {
    console.log("initialize routine")
    await initKaspaFramework()
};

app.listen(process.env.PORT || 3000)
init();
