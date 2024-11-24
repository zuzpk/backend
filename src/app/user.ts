import { ADMIN_EMAIL, APP_NAME, APP_URL, SESS_DURATION, SESS_KEYS, SESS_PREFIX, TBL_USERS } from "../config";
import { Decode, Encode, fromHash, headers, numberInRange, sendMail, toHash, urldecode } from "../lib/core";
import type { Request, Response } from "express";
import DB from "../lib/db";
import { Logger } from "../lib/logger";
import { dynamicObject } from "../lib/types";
import jwt from "jsonwebtoken";

const uname = (u: dynamicObject) => u.fullname == `none` ? u.email.split(`@`)[0] : u.fullname

const youser = async (u: dynamicObject, cc?: string) => {

    const [ country, stamp ] = u.signin.split(`@@`)

    return {
        ID: toHash(u.ID),        
        nm: uname(u),
        em: u.email.trim(),
        cc: cc || country,
        status: u.status
    }

}

export const withSession = async (req, resp, raw = true) => {

    return new Promise((resolve, reject) => {
        
        const { userAgent, cfIpcountry } = headers(req)
        const country = cfIpcountry || `unknown`
        const payload = req.body

        try{

            const _auth : string[] = []

            for( const c in payload ){
                if ( SESS_KEYS.includes( c.replace(SESS_PREFIX, ``) ) ){
                    _auth.push(c)
                }
            }

            if ( _auth.length != SESS_KEYS.length ){                
                return reject({
                    error: `oauth`,
                    message: `You are not authorized for this action`
                })
            }

            const _uid = payload[`${SESS_PREFIX}ui`]
            const _sid = payload[`${SESS_PREFIX}si`]

            const uid = fromHash(_uid)
            const sid = fromHash(_sid)

            if ( !_uid || !_sid || !uid || !sid ){
                return reject({
                    error: `oauth`,
                    message: `Well played!. You are not authorized for this action`
                })
            }

            Promise.all([
                DB.SELECT("SELECT uid FROM users_sess WHERE ID=? AND expiry>? AND status=?", [sid, Date.now(), 1]),
                DB.SELECT("SELECT * FROM users WHERE ID=?", [uid]),            
            ])
            .then(([sess, user]) => {

                const u = user.row!

                if ( uid != sess.row!.uid ){
                    return reject({
                        error: `oauth`,
                        message: `Your session is expired. Sign in again.`
                    })
                }

                if ( u.status == -1 ){
                    return reject({
                        error: `oauth`,
                        message: `You are banned from ${APP_NAME}.`
                    })
                }

                Update(u.ID, {
                    signin: `${country}@@${Date.now()}`
                })
                .then(x => {
                    if ( raw )
                        resolve(user)
                    else
                        resolve({
                            kind: `oauth`,
                            u: youser(user)
                        })
                })
                .catch(err => {
                    console.log(`[withUserSessError2]`, err)
                    reject({
                        error: `oauth`,
                        message: `your session token is invalid. signin again.`
                    })
                })

            })
            .catch(err => {
                console.log(`[withUserSessError]`, err)
                reject({
                    error: `oauth`,
                    message: `Session token is invalid.`
                })
            })


        }catch(e){
            reject({
                error: `serverBusy`,
                message: `This is not you. this is us.`
            })
        }

    })

}

export const Update = async ( uid: number | string, data: dynamicObject ) => {

    const query = [`UPDATE users SET`]
    const fields : string[] = []
    const values : any[] = []
    uid = uid.isNumber() ? uid : fromHash(uid as string)

    Object.keys(data).forEach(key => {
        fields.push(`${key}=?`)
        values.push(data[key])
    })

    query.push(fields.join(`, `), `WHERE ID=?`)

    return DB.UPDATE(query.join(` `), [...values, uid])

}

export const Signin = async (req: Request, resp: Response) => {

    const { userAgent, cfIpcountry : country } = headers(req)
    
    const { em, psw } = req.body

    if ( !em || em.isEmpty() || !psw || psw.isEmpty() ){
        return resp.send({
            error: `invalidData`,
            message: `Email and password are required.`
        })
    }

    if ( !em.isEmail() ){
        return resp.send({
            error: `invalidData`,
            message: `Provide valid email address.`
        })
    }

    DB.SELECT(`SELECT * FROM users WHERE email=?`, [em.toLowerCase().trim()])
    .then(user => {

        const u = user.row!
        
        // console.log(u.password, Encode(psw))
        if ( u.password != Encode(psw) ){   
            return resp.send({
                error : 'invalidPassword',
                message : 'Your password is wrong. Try again with correct password.'
            })
        }

        if ( u.status == -1 ){
            return resp.send({
                error: `accountBanned`,
                message: `You are banned from ${APP_NAME}.`
            })
        }

        const geo = `${country}@@${Date.now()}`
        
        Update(
            u.ID,
            {
                signin: geo,
            }
        )
        .then(r => {
            DB.INSERT(
                "INSERT INTO users_sess (uid,token,expiry,uinfo) VALUES (?,?,?,?)",
                [
                    u.ID,
                    Encode( `${u.ID}@@${u.email}@@${u.password}@@${Date.now()}` ),
                    Date.now() + SESS_DURATION,
                    geo
                ]
            )
            .then(async sess => {
                
                return resp.send({
                    kind: `oauth`,
                    u: {
                        ui: toHash(u.ID),
                        ut: jwt.sign(
                            {
                                em: u.email.trim(),
                                cc: country,
                                ts: Date.now()
                            }, 
                            process.env.ENCRYPTION_KEY!,
                            {
                                audience: APP_NAME.replace(/\s+/g, `-`).toLowerCase(),
                                issuer: APP_NAME,
                                expiresIn: Date.now() + SESS_DURATION
                            }
                        ),
                        ud: await youser(u, country),
                        fp: toHash(u.ID),
                        si: toHash(sess.id)
                    },
                    message: `Good Job!`
                })
            })
            .catch(err => {
                Logger.log(`[SigninFailed:A]`, err.message)
                resp.send({
                    error: `oauth`,
                    message: `Signin failed. Try again.`
                })
            });
        })
        .catch(err => {
            Logger.log(`[SigninFailed:B]`, err)
            resp.send({
                error: `oauth`,
                message: `signin request failed. try again.`
            })
        })


    })
    .catch(err => {

        Logger.error(`[SigninFailed]`, err)
        return resp.send({
            error: `invalidEmail`,
            message: `That email address is not associated with any account.`
        })

    })

}

export const Signup = async (req: Request, resp: Response) => {

    const { userAgent, cfIpcountry : country } = headers(req)
    
    const { nm, em, repassw: passw } = req.body

    if ( !em || em.isEmpty() || !passw || passw.isEmpty() ){
        return resp.send({
            error: `invalidData`,
            message: `Email and password are required.`
        })
    }

    if ( !em.isEmail() ){
        return resp.send({
            error: `invalidData`,
            message: `Provide valid email address.`
        })
    }

    const [ name, tld ] = em.toLowerCase().trim().split(`@`)

    const checkTLD = await fetch(`http://${tld}`)

    if ( checkTLD.status != 200 ){
        return resp.send({
            error: `invalidData`,
            message: `Invalid domain for email address.`
        })
    }

    const email = `${name}@${tld}`.toLowerCase().trim()

    return DB.SELECT(`SELECT ID FROM users WHERE email=? LIMIT 1`, [email])
    .then(data => {
        return resp.send({
            error : 'EmailAlreadyTaken',
            message : 'A user with that email already exist.'
        })
    })  
    .catch(err => {
        
        //New
        const geo = `${country}@@${Date.now()}`    
        const ucode = numberInRange(111111, 999999)
        const utoken = toHash(ucode);
        const password = Encode(passw)

        let reff = 0
        if ( `__urf` in req.body ){
            reff = fromHash(req.body.__urf) || 0
        }

        DB.INSERT(
            `INSERT INTO users (token,ucode,email,password,fullname,reff,joined,signin) VALUES (?,?,?,?,?,?,?,?)`,
            [utoken, ucode, email, password, nm, reff, geo, geo]
        )
        .then(save => {

            const otpToken = Encode(`signup@@${save.id}@@${ucode}@@${Date.now()}`)
            const verifyToken = Encode(`signup@@${save.id}@@${utoken}@@${Date.now()}`)

            const verifyMessage = [
                `<div style="max-width:600px;font-size:16px;text-align:center;margin:0 auto;">`,
                `Welcome to <b>${APP_NAME}</b>`,
                `Use this code to finish setting up your account`,
                `<div style="padding:30px 0px 0px 0px;text-align:center;font-size:50px;font-weight:bold;">${ucode}</div>`,
                `<div style="padding:0px 0px 30px 0px;text-align:center;">`,
                `or use this link to verify your account:<br />`,
                `<a href="${APP_URL}u/verify/${verifyToken}">${APP_URL}u/verify/${verifyToken}</a></div>`,
                `If you don't recognize <b>${em}</b>, you can safely ignore this email`,
                `</div>`
            ].join(`<br />`)

            sendMail(
                `${APP_NAME} <${ADMIN_EMAIL}>`, 
                email, 
                `Email verification code: ${ucode}`, 
                verifyMessage, 
            )
            .then(r => {
                resp.send({
                    kind: `accountCreated`,
                    token: otpToken,
                    email,
                    message: `Goog job! Your account has been created.`
                })
            })
            .catch(err => {
                Logger.error(`[signupError]`, err)
                return resp.send({
                    error: `accountNotCreated`,
                    message: `your account was not created, try again.`
                })
            })

        })
        .catch(err => {
            Logger.error(`[signupErrored]`, err)
            return resp.send({
                error: `accountNotCreated`,
                message: `your account was not created, try again.`
            })
        })

    })

    

}

export const Recover = async (req: Request, resp: Response) => {

    const { userAgent, cfIpcountry : country } = headers(req)
    
    const { em } = req.body

    if ( !em || em.isEmpty() || !em.isEmail() ){
        return resp.send({
            error: `invalidData`,
            message: `Provide valid email address.`
        })
    }

    DB.SELECT(`SELECT * FROM users WHERE email=?`, [em.toLowerCase().trim()])
    .then(user => {

        const u = user.row!

        if ( u.status == -1 ){
            return resp.send({
                error: `accountBanned`,
                message: `You are banned from ${APP_NAME}.`
            })
        }

        const ucode = numberInRange(111111, 999999)
        const token = toHash(ucode);


        Update(
            u.ID,
            {
                token, ucode,
            }
        )
        .then(save => {
            
            const otpToken = Encode(`recover@@${u.ID}@@${ucode}@@${Date.now()}`)
            const verifyToken = Encode(`recover@@${u.ID}@@${token}@@${Date.now()}`)

            const verifyMessage = [
                `<div style="max-width:600px;font-size:16px;text-align:center;margin:0 auto;">`,
                `Reset your password`,
                `If you requested a password reset for your ${APP_NAME} account, below is your reset code. If you didn\'t make this request, ignore this email.`,
                `<div style="padding:30px 0px 0px 0px;text-align:center;font-size:50px;font-weight:bold;">${ucode}</div>`,
                `<div style="padding:0px 0px 30px 0px;text-align:center;">`,
                `or use this link to recover your account:<br />`,
                `<a href="${APP_URL}u/recover/verify/${verifyToken}">${APP_URL}u/recover/verify/${verifyToken}</a></div>`,
                `If you don't recognize <b>${em}</b>, you can safely ignore this email`,
                `</div>`
            ].join(`<br />`)

            sendMail(
                `${APP_NAME} <${ADMIN_EMAIL}>`, 
                u.email.trim(), 
                `Account recovery code: ${ucode}`, 
                verifyMessage, 
            )
            .then(r => {
                resp.send({
                    kind: `verificationCodeSent`,
                    token: otpToken,
                    email: u.email,
                    message: `Recovery code sent.`
                })
            })
            .catch(err => {
                Logger.error(`[recoveryError]`, err)
                return resp.send({
                    error: `recoveryNotSent`,
                    message: `recover code was not sent, try again.`
                })
            })

        })
        .catch(err => {
            Logger.log(`[RecoveryFailed:B]`, err)
            resp.send({
                error: `oauth`,
                message: `account recovery request failed. try again.`
            })
        })


    })
    .catch(err => {
        Logger.error(`[RecoveryFailed]`, err)
        return resp.send({
            error: `invalidEmail`,
            message: `That email address is not associated with any account.`
        })

    })

}

export const RecoverUpdate = async (req: Request, resp: Response) => {
    
    const { token, repassw } = req.body
    const [ mode, uid, ucode, utoken ] = Decode( token ).split(`@@`)

    DB.SELECT(`SELECT * FROM users WHERE ID=? AND token=? AND ucode=?`, [uid, utoken, ucode])
        .then(user => {

            const code = numberInRange(111111, 999999)
            const voken = toHash(code);

            Update(
                uid,
                {
                    token: voken,
                    ucode: code,
                    password: Encode(repassw),
                }
            )
            .then(save => {
                return resp.send({
                    kind: `recoverySuccess`,
                    name: user.row!.fullname,
                    message: `Your password has been updated.`
                })
            })
            .catch(err => {

                Logger.error(`[recoveryFailed:A]`, err)

                resp.send({
                    error: `recoveryFailed`,
                    message: `We can't update your password right now.`
                })

            })

        })
        .catch(err => {

            resp.send({
                error: `recoveryFailed`,
                message: `Security token mismatched.`
            })

        })

}

export const Verify = async (req: Request, resp: Response) => {

    const { token, otp } = req.body

    if( !token || token.isEmpty() ){
        return resp.send({
            error: `invalidData`,
            message: `VerificationToken is required.`
        })
    }
    
    const [ mode, uid, ucode, expiry ] = Decode( token ).split(`@@`)

    if ( otp ){

        if ( ucode != otp ){
            return resp.send({
                error: `verificationFailed`,
                message: `Verification code is either expired or invalid. please try again.`
            })
        }

    }

    return (otp ? 
            DB.SELECT("SELECT ID, fullname, status FROM users WHERE ID=? AND ucode=? AND status!=?", [uid, ucode, -1])
            : DB.SELECT("SELECT ID, fullname, status FROM users WHERE ID=? AND token=? AND status!=?", [uid, ucode, -1])
        )
        .then(user => {
            
                const u = user.row!

                if ( mode.equals(`signup`) && u.status == 1 ){
                    return resp.send({
                        error: `verificationFailed`,
                        code: 101,
                        message: `You have already verified your account.`
                    })
                }

                const ucode = numberInRange(111111, 999999)
                const token = toHash(ucode);
                
                return DB.UPDATE(`UPDATE users SET token=?, ucode=?, status=? WHERE ID=?`, 
                    [token, ucode, u.status == 0 ? 1 : u.status, uid])
                .then(save => {
                    return resp.send({
                        kind: `verificationSuccess`,
                        name: u.fullname,
                        token: mode.equals(`recover`) ? Encode(`update@@${u.ID}@@${ucode}@@${token}@@${Date.now()}`) : `-`,
                        message: `Your account has been verified.`
                    })
                })
                .catch(err => {
                    Logger.error(`[verifyError]`, err)
                    return resp.send({
                        error: `verificationFailed`,
                        code: 102,
                        message: `Verification was not successful. please try again.`
                    })
                })
            
        })
        .catch(err => {
            Logger.error(`[verifyTokenError]`, err)
            return resp.send({
                error: `verificationFailed`,
                code: 102,
                message: `Verification code is either invalid or expired. please try again.`
            })
        })

}

export const Signout = async (req: Request, resp: Response) => {
    withSession(req, resp)
    .then(s => {
        const si = fromHash(req.body[`${SESS_PREFIX}si`])
        DB.DELETE(`DELETE FROM users_sess WHERE ID=?`, [si])
        .then(del => {
            resp.send({
                kind: `signoutSuccess`,
                message: `You have been signed out.`
            })
        })
        .catch(err => {
            resp.send({
                error: `signoutFailed`,
                message: `Failed to signout. Please try again.`
            })    
        })
    })
    .catch(e => {
        resp.send(e)
    })
}

