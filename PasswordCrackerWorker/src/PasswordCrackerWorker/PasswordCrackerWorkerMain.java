package PasswordCrackerWorker;

import org.apache.thrift.TException;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.protocol.TProtocol;
import org.apache.thrift.server.TServer;
import org.apache.thrift.server.TThreadedSelectorServer;
import org.apache.thrift.transport.*;
import thrift.gen.PasswordCrackerMasterService.PasswordCrackerMasterService;
import thrift.gen.PasswordCrackerWorkerService.PasswordCrackerWorkerService;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.*;

import static PasswordCrackerWorker.PasswordCrackerConts.INITIAL_DELAY;
import static PasswordCrackerWorker.PasswordCrackerConts.INTERVAL;


public class PasswordCrackerWorkerMain {
    public static ScheduledExecutorService transferPool = Executors.newScheduledThreadPool(2);
    public static String workerHostAddress;

    static {
        try {
            workerHostAddress = InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            if (args.length != 3) {
                System.err.println("USAGE : PasswordCrackerWorker MasterAddress MasterPort workerPort");
            }
            String masterAddress = args[0];
            int masterPort = Integer.parseInt(args[1]);
            int workerPort = Integer.parseInt(args[2]);

            TTransport workerTransport = new TSocket(masterAddress, masterPort);
            workerTransport.open();    // Connect to master

            // After connecting to Master...
            TProtocol protocol = new TBinaryProtocol(workerTransport);
            PasswordCrackerMasterService.Client masterService = new PasswordCrackerMasterService.Client(protocol);

            // Periodically execute the transferHeartBeat method.
            transferPool.scheduleAtFixedRate(() -> {
                transferHeartBeat(masterService);
            }, INITIAL_DELAY, INTERVAL, TimeUnit.SECONDS);

            executeWorkerServer(workerPort);

        } catch (TTransportException e) {
            e.printStackTrace();
        }
    }

    // Service Direction : worker -> master
    public static void executeWorkerServer(int workerPort) {
        try {
            PasswordCrackerWorkerServiceHandler workerServiceHandler = new PasswordCrackerWorkerServiceHandler();
            PasswordCrackerWorkerService.Processor masterRequestProcessor = new PasswordCrackerWorkerService.Processor(workerServiceHandler);

            TNonblockingServerTransport serverTransport = new TNonblockingServerSocket(workerPort);

            TThreadedSelectorServer.Args workerServerArgs = new TThreadedSelectorServer.Args(serverTransport);
            workerServerArgs.transportFactory(new TFramedTransport.Factory());
            workerServerArgs.protocolFactory(new TBinaryProtocol.Factory());
            workerServerArgs.processor(masterRequestProcessor);
            workerServerArgs.selectorThreads(4);
            workerServerArgs.workerThreads(32);

            TServer server = new TThreadedSelectorServer(workerServerArgs);

            server.serve();
        } catch (TTransportException e) {
            e.printStackTrace();
        }
    }

    // Transfer heartbeat to master

    public static void transferHeartBeat(PasswordCrackerMasterService.Client masterService) {
        /** COMPLETE **/
    }
}
