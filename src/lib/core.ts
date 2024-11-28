import Hashids from "hashids"
import crypto from 'crypto'
import de from "dotenv"
import { Request } from "express"
import { dynamicObject } from "./types";
import nodemailer from 'nodemailer'
import { Logger } from "./logger";

de.config()
const encryptionAlgo = 'aes-256-cbc';
const hashids = new Hashids(process.env.ENCRYPTION_KEY, +process.env.HASHIDS_LENGTH!)

export const toHash = ( str : number ) : string => hashids.encode(str)

export const fromHash = ( str : string ) : number => {
    const n = hashids.decode(str)
    return n.length >= 0 ? Number(n[0]) : 0
}


const safeB64Encode = (str: string): string => {
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const safeB64Decode = (str: string): string => {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    return str //Buffer.from(str, 'base64').toString('utf8');
}

const encryptKey = (key?: string): Buffer => crypto.createHash('sha256').update(key || process.env.ENCRYPTION_KEY!).digest();

export const Encode = (value: string, key?: string): string => {
    if (!value) return ``;
    const ENCRYPT_KEY = encryptKey(key);
    const iv = crypto.createHash('md5').update(ENCRYPT_KEY).digest('hex').substring(0, 16);
    const cipher = crypto.createCipheriv(encryptionAlgo, Buffer.from(ENCRYPT_KEY), iv);
    let encrypted = cipher.update(value, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return safeB64Encode(encrypted);
}

export const Decode = (value: string, key?: string): string => {
    if (!value) return ``
    try {
        const ENCRYPT_KEY = encryptKey(key);
        const iv = crypto.createHash('md5').update(ENCRYPT_KEY).digest('hex').substring(0, 16);
        const decipher = crypto.createDecipheriv(encryptionAlgo, Buffer.from(ENCRYPT_KEY), iv);
        let decrypted = decipher.update(safeB64Decode(value), 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }catch(err : any){
        Logger.error(`[DecodeFailed]`, value, key || `APP_KEY`, err)
        return ``
    }
}

export const withGlobals = () => {
    Object.prototype.isTypeof = function(v : any){ return typeof this === typeof v }
    Object.prototype.isFunction = function(){ return typeof this === `function` }
    Object.prototype.equals = function(v : any){ return this === v }
    Object.prototype.isNull = function(){ return this === null }
    Object.prototype.isString = function(){ return typeof this == `string` }
    Object.prototype.isNumber = function(){ return /^[+-]?\d+(\.\d+)?$/.test(this as string) }
    Object.prototype.isObject = function(){ return typeof this == `object` && !Array.isArray(this!) && this! !== null }
    Object.prototype.isArray = function(){ return Array.isArray(this!) }
    Object.prototype.isEmpty = function(){
        if(Array.isArray(this))
            return this.length === 0
        else if(`object` === typeof this!)
            return Object.keys(this!).length == 0
        else
            return this! == "" || (this! as string).length == 0
    }
    Object.prototype.toLowerCase = function(){ 
        if ( typeof this === "string" ){
            return (String.prototype.toLocaleLowerCase || String.prototype.toLowerCase)(this);
        }
        return String(this).toLocaleLowerCase()
    }
    String.prototype.isEmail = function(){ return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(this as string);  }
    String.prototype.isUrl = function(){
        return /^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/[^\s]*)?$/.test(this as string);
    }
    String.prototype.camelCase = function(){
        return this
            .split(/[^a-zA-Z0-9]+/)    // Split by any non-alphanumeric character
            .map((word, index) =>
                index === 0
                    ? word
                    : word.charAt(0).toUpperCase() + word.slice(1)
            )
            .join('');
    }
    String.prototype.ucfirst = function(){
        return `${this.charAt(0).toUpperCase()}${this.substring(1, this.length)}`
    }
}

export const pluralize = (word: string, count : number) => `${word}${count !== 1 ? 's' : ''}`

export const headers = (req: Request, keys?: string[]) : dynamicObject => {

    const list = {}
    keys = keys || [];

    (keys.length > 0 ? keys : Object.keys(req.headers)).map(key => {
        if ( keys.length > 0 && req.headers[key] ){
            list[key.camelCase()] = req.headers[key]
        }
        else{
            list[key.camelCase()] = req.headers[key]
        }
    })

    return list

}

export const numberInRange = (min: number, max: number) => {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

export const uuid = (len: number) => toHash(numberInRange(11111111111, 999999999999))

export const sendMail = (from : string, to : string, subject : string, message : string) => {

    return new Promise((resolve, reject) => {

        const sender = nodemailer.createTransport({
            service: process.env.EMAIL_SERVICE,
            host: process.env.EMAIL_HOST,
            port: Number(process.env.EMAIL_PORT),
            secure: true,
            auth: {
                user: process.env.EMAIL_ADDRESS,
                pass: process.env.EMAIL_PASSWORD
            }
        })

        sender.sendMail(
            {
                from, to, subject, html: message
            },
            (error, info) => {
                if ( error ){
                    reject(error)
                }
                else
                    resolve(info.response)
            }
        )

    })

}

export const urldecode = (str: string) => decodeURIComponent(str.replace(/\+/g, '%20'))

export const urlencode = (str: string) => encodeURIComponent(str)