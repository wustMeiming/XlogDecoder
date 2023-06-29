package com.meizu.sysmonitor;

public class Main {
    public static void main(String[] args) {
        if (args.length < 1){
            System.out.println("Usage: java -jar XlogDecoder.jar [infile] [outfile]");
            return;
        }
        String infile, outfile;
        infile = args[0];
        if (args.length<2) {
            outfile = infile + ".xlog";
        }else {
            outfile = args[1];
        }
        //TODO type your private key
        String xlogPrivKey = System.getenv("XLOG_PRIV_KEY");
        if (xlogPrivKey != null) {
            XlogFileDecoder.PRIV_KEY = xlogPrivKey;
        }
        //TODO type your public key
        String xlogPubKey = System.getenv("XLOG_PUB_KEY");
        if (xlogPubKey != null) {
            XlogFileDecoder.PUB_KEY = xlogPubKey;
        }
        XlogFileDecoder.ParseFile(infile, outfile);
    }
}
