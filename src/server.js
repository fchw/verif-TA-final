import express from "express";
import cors from "cors"
import fileUpload from "express-fileupload";
import fs from "fs";
import pkg from '@ninja-labs/verify-pdf';  // ES6 
import { VerifyPdf } from "./index.js";

const port =  process.env.PORT || 8080
const app = express();
app.use(cors())
// app.use(multer({dest:'./uploads/'}));
app.use(fileUpload());
app.use(express.json())
app.use(express.urlencoded());
app.set('view engine', 'ejs');
app.use( express.static( "public" ) );
app.use( express.static( "views" ) );

app.get("/", (req,res) => {
    res.render("index.ejs")
})

app.post("/result", (req,res) => {
    const file = req.files.file
    const sign = new VerifyPdf();

    let data = {}
    data.verified = sign.verify(file.data);
    const { getCertificatesInfoFromPDF } = pkg;
    if(data.verified.status){
        data.reason = sign.reason(file.data);
        data.date = sign.date(file.data)
        data.certs = getCertificatesInfoFromPDF(file.data);
    }
    else
        data.reason = data.date = data.certs = null
    res.render("result.ejs",data)
})

app.listen(port, () => {
    console.log(`Listening ${port}`)
})
