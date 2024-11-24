import mysql, { Pool, PoolOptions, RowDataPacket, FieldPacket, ResultSetHeader } from 'mysql2/promise'
import { Logger } from './logger';

export type selectQueryResult = [RowDataPacket[], FieldPacket[]];

class Database {
    
    pool: Pool | null

    constructor(){
        this.pool = null;
    }


    createPool(){
        if ( !this.pool ){
            this.pool = mysql.createPool({
                host: process.env.DB_HOST!,
                user: process.env.DB_USER!,
                password: process.env.DB_PASSWORD!,
                port: process.env.DB_PORT!,
                database: process.env.DB_NAME!,
                waitForConnections: process.env.DB_WAIT_FOR_CONNECTIONS!,
                connectionLimit: process.env.DB_CONNECTION_LIMIT!,
                maxIdle: process.env.DB_MAX_IDLE!,
                idleTimeout: process.env.DB_IDLE_TIMEOUT!,
                queueLimit: process.env.DB_QUEUE_LIMIT!,
                connectTimeout: process.env.DB_CONNECT_TIMEOUT!,
                enableKeepAlive: process.env.DB_ENABLE_KEEP_ALIVE!,
                keepAliveInitialDelay: process.env.DB_KEEP_ALIVE_INITIAL_DELAY!,
                multipleStatements: process.env.DB_MULTIPLE_STATEMENTS!
            } as unknown as PoolOptions)
        }
    }

    execute(query: string, values: any[]) : Promise<selectQueryResult>{

        const self = this
        self.createPool()

        return new Promise<selectQueryResult>(async (resolve, reject) => {
            try{

                const rest = await self.pool!.execute(query, values)
                resolve(rest as selectQueryResult)

            }catch(e){
                console.log(`DBExecError`, e)
                const error = e as any;
                reject({
                    code: error.code || `UNKNOWN`,
                    errno: error.errno || 0,
                    state: error.sqlState || `UNKNOWN`,
                    message: error.sqlMessage || `UNKNOWN`
                });  
            }
        })
    }

    async SELECT(query: string, values: any[]) : Promise<{
        hasRows: boolean,
        count: number,
        row: RowDataPacket | null,
        rows: RowDataPacket[]
    }>{

        const self = this

        return new Promise(async (resolve, reject) => {

            try{
                const [response, fields] = await self.execute(query, values)
                if  (!response || response.length == 0 ){
                    reject({ hasRows: false, errno: -1 })
                }
                resolve({ 
                    hasRows: response.length > 0, 
                    count: response.length,
                    row: response.length > 0 ? response[0] : null,
                    rows: response
                })
            }catch(e){
                console.log(`DBSelectError`, e)
                reject({
                    hasRows: false,
                    ...e as any
                })
            }
            
        })        
    }

    async INSERT(query: string, values: any[]) : Promise<{ id: number }>{

        const self = this

        return new Promise(async (resolve, reject) => {

            try{
                const [response, fields] = await self.execute(query, values)
                if  ( Number(response['insertId']) > 0 ){
                    resolve({ 
                        id: Number(response['insertId'])
                    })
                }
                else {
                    reject({ saved: false, errno: -1, id: 0 })
                }
            }catch(e){
                Logger.log(`DBInsertError`, e)
                reject({
                    saved: false,
                    ...e as any
                })
            }

        })        
    }

    async UPDATE(query: string, values: any[]){

        const self = this

        return new Promise(async (resolve, reject) => {

            try{
                const [response, fields] = await self.execute(query, values)
                if ( Number(response['affectedRows']) > 0 )
                    resolve({ updated: true })
                else
                    reject({ updated: false, errno: -1 })

            }catch(e){
                Logger.log(`DBUpdateError`, e)
                reject({
                    updated: false,
                    ...e as any
                })
            }

        })        
    }

    async DELETE(query: string, values: any[]){
        
        const self = this

        return new Promise(async (resolve, reject) => {
            try{

                const [response, fields] = await self.execute(query, values)
                if ( Number(response['affectedRows']) > 0 )
                    resolve({ deleted: true })
                else
                    reject({ deleted: false, errno: -1 })

            }catch(e){
                Logger.log(`DBDeleteError`, e)
                reject({
                    deleted: false,
                    ...e as any
                })
            }
            
        })
        
    }

}

const DB = new Database()

export default DB