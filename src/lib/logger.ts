import winston from "winston"
import { Request, Response, NextFunction } from "express"
import { headers } from "./core"
import { dynamicObject } from "./types"

export const Logger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp({ format: "YYYY/MM/DD HH:mm:ss" }),
        winston.format.splat(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level}] ${message}`
        })
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.timestamp({ format: "YYYY/MM/DD HH:mm:ss" }),
                winston.format.splat(),
                winston.format.printf(({ timestamp, level, message }) => {
                    return `${timestamp} [${level}] ${message}`
                })
            ),
        }),
        new winston.transports.File({ filename: "error.log", level: "error" }),
        new winston.transports.File({ filename: "combined.log" }),
    ]
})

const accessLogger = winston.createLogger({
    level: "info",
    format: winston.format.combine(
        winston.format.timestamp({ format: "YYYY/MM/DD HH:mm:ss" }),
        winston.format.splat(),
        winston.format.printf(({ message }) => {
            const { userIP, userAgent, country, method, url, timestamp } = message as dynamicObject
            return `${country || `Anonymous`} (${userIP || `?`}): [${timestamp}] "${method} ${url}" "${userAgent}"`
        })
    ),
    transports: [
        new winston.transports.File({ filename: "access.log" }),
    ]
})

export const withAccessLogger = (req: Request, res: Response, next: NextFunction) => {
        
    const { userAgent, cfIpcountry : country, xForwardedFor  } = headers(req) 
    accessLogger.info({ 
        userIP: xForwardedFor,
        userAgent,
        country,
        method: req.method, 
        url: req.url  
    })

    next()

}