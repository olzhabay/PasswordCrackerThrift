package PasswordCrackerClient;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.transport.*;
import thrift.gen.PasswordCrackerMasterService.PasswordCrackerMasterService;


public class PasswordCrackerClient {
    public static void main(String[] args) throws TException {
        if (args.length != 3) {
            System.err.println("USAGE : MasterAddress MasterPort encryptedPassword");
            return;
        }
        String masterAddress = args[0];
        int port = Integer.parseInt(args[1]);
        String encryptedPassword = args[2];

        try {
            TTransport transport;
            transport = new TSocket(masterAddress, port);
            transport.open();   // Connect Socket (ipAddress, port) to master

            TProtocol protocol = new TBinaryProtocol(transport);
            
            PasswordCrackerMasterService.Client passwordCrackerService = new PasswordCrackerMasterService.Client(protocol);
            // Decrypt call to master
            String password = passwordCrackerService.decrypt(encryptedPassword);
            // Decrypt call to master
            System.out.println("encryptedPassword : " + encryptedPassword + "\npassword : " + password);
            transport.close();
        } catch (TTransportException e) {
            e.printStackTrace();
        } catch (TException e) {
            e.printStackTrace();
        }
    }
}
