package PasswordCrackerMaster;

import org.apache.thrift.server.TServer;
import org.apache.thrift.server.TThreadPoolServer;
import org.apache.thrift.transport.TTransportException;
import org.json.simple.parser.JSONParser;
import thrift.gen.PasswordCrackerMasterService.PasswordCrackerMasterService;

import java.io.FileReader;
import java.util.HashMap;

public class PasswordCrackerMasterMain {
    public static void main(String[] args) {
        int port = Integer.parseInt(args[0]);
        PasswordCrackerMasterServiceHandler masterServiceHandler = new PasswordCrackerMasterServiceHandler();
        PasswordCrackerMasterService.Processor clientRequestProcessor = new PasswordCrackerMasterService.Processor(masterServiceHandler);
        try {
            JSONParser parser = new JSONParser();
            // WorkrInfoList.json parsing
            HashMap<String, Integer> workerInfoMap = (HashMap<String, Integer>) parser.parse(new FileReader("/Users/bong/Documents/Project/PasswordCrackerInThrift3/PasswordCrackerMaster2/WorkerInfoList.json"));

            PasswordCrackerTransport transport = new PasswordCrackerTransport(port, workerInfoMap);

            TServer server = new TThreadPoolServer(new TThreadPoolServer.Args(transport).processor(clientRequestProcessor));
            System.out.println("Starting the Server...");
            server.serve();

        } catch (TTransportException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
