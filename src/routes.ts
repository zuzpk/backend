import { dynamicObject } from "./lib/types";
import { OAuth, Recover, RecoverUpdate, Signin, Signout, Signup, Verify } from "./app/user";
import { Request, Response } from "express";
import DB from "./lib/db";
import { Decode, Encode } from "./lib/core";

const Routes : dynamicObject = {
    Get: {
        Ping: (req: Request, resp: Response) => resp.json({ message: "pong" }),
        Test: (req: Request, resp: Response) => {
            const t = Encode("test")
            console.log(t) 
            console.log(`dec`, Decode(t)) 
            resp.json({ message: "pong" })
        },
    },
    Post: {
        U: { OAuth, Signup, Verify, Signin, Recover, RecoverUpdate, Signout }
    }
}

export default Routes