import express, { Request, Response } from "express"
import de from "dotenv"
import cors from "cors"
import cookieParser from "cookie-parser"
import http from "http"
import WebSocket, { WebSocketServer } from "ws"
import { API_KEY, APP_VERSION } from "./config"
import { Decode, withGlobals } from "./lib/core"
import Routes from "./routes"
import { withAccessLogger } from "./lib/logger"

de.config()
withGlobals()

const port = 3001
const app = express();

app.use(
    cors(), 
    cookieParser(), 
    express.json(),
    withAccessLogger
)

const httpServer = http.createServer(app)
const wss = new WebSocketServer({ server: httpServer })

const handleAPI = (requestMethod: "Post" | "Get", req: Request, resp: Response) => {

    const [ key, method, action, ...rest ] = req.url.split(`/`).filter(Boolean)
    
    if ( key == API_KEY && method ){
        try{

            const apiRoutes = Routes[requestMethod]
            const METHOD = method.camelCase().ucfirst()
            const ACTION = action ? action.camelCase().ucfirst() : null

            if ( METHOD in apiRoutes ){

                if ( apiRoutes[METHOD].isFunction() ){
                    return apiRoutes[METHOD](req, resp)    
                }
                
                else if( 
                    ACTION &&
                    apiRoutes[METHOD].isObject() && 
                    ACTION in apiRoutes[METHOD] 
                ){
                    return apiRoutes[METHOD][ACTION](req, resp)
                }

                return resp.status(403).send({
                    error: `403`,
                    message: `almost there :) try again with correct action.`
                })
                
            }

            return resp.status(403).send({
                error: `403`,
                message: `almost there :) try again with correct method.`
            })

        }catch(e){
            console.log(e)
            return resp.status(403).send({
                error: `403`,
                message: `you are lost buddy.`
            })

        }
    }

    return resp.status(404).send({
        error: `404`,
        message: `you are lost buddy.`
    })
}

app.get(`*`, (req: Request, resp: Response) => handleAPI("Get", req, resp))
app.post(`*`, (req: Request, resp: Response) => handleAPI("Post", req, resp))

httpServer.listen(port, () => console.log(`Watching you on port`, port, `:)`) )