package PasswordCrackerMaster;

import org.apache.thrift.transport.TServerSocket;
import org.apache.thrift.transport.TServerTransport;
import org.apache.thrift.transport.TSocket;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;

import java.net.Socket;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;

import static PasswordCrackerMaster.PasswordCrackerConts.HEART_BEAT_INITIAL_DELAY;
import static PasswordCrackerMaster.PasswordCrackerConts.HEART_BEAT_INTERVAL;
import static PasswordCrackerMaster.PasswordCrackerConts.NUMBER_OF_WORKER;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.checkHeartBeat;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.heartBeatCheckPool;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.workersAddressList;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.workersSocketList;

public class PasswordCrackerTransport extends TServerTransport {
    public final TServerSocket serverSocket;
    public final HashMap<String, Integer> workersInfoMap;

    public PasswordCrackerTransport(int port, HashMap<String, Integer> workerInfoMap) throws TTransportException {
        this.serverSocket = new TServerSocket(port);
        this.workersInfoMap = workerInfoMap;
    }

    @Override
    public void listen() throws TTransportException {
        serverSocket.listen();
    }

    @Override
    public void close() {
        serverSocket.close();
    }

    // After connecting to the workers registered in WorkerInfoList.json and receives the client request.
    // And when the number of workers assigned to the Master is connected, the heartbeat of the connected worker is checked.

    @Override
    protected TTransport acceptImpl() throws TTransportException {
        try {
            Socket socket = this.serverSocket.getServerSocket().accept();
            String connectedAddress = socket.getInetAddress().getHostAddress();

            // workers : Object List for RPC
            if (workersAddressList.size() < NUMBER_OF_WORKER && workersInfoMap.containsKey(connectedAddress)) {
                TSocket workerSocket = new TSocket(socket);
                String workerAddress = socket.getInetAddress().getHostAddress();
                workersSocketList.add(workerSocket);
                workersAddressList.add(workerAddress);

                if (workersAddressList.size() == NUMBER_OF_WORKER) {
                    heartBeatCheckPool.scheduleAtFixedRate(() -> {
                        checkHeartBeat();
                    }, HEART_BEAT_INITIAL_DELAY, HEART_BEAT_INTERVAL, TimeUnit.SECONDS);
                }

                System.out.println("numberOfWorker : " + workersAddressList.size());

                if (workersAddressList.size() == NUMBER_OF_WORKER) {
                    System.out.println("Wait for Client");
                }
                return workerSocket;
            } else if (workersAddressList.size() >= NUMBER_OF_WORKER) {
                return new TSocket(socket);
            } else {
                socket.close();
                return null;
            }

        } catch (Exception e) {
            System.out.println("acceptImpl() : Connection Error");
            e.printStackTrace();
        }
        throw new TTransportException(1, "No underlying server socket.");
    }
}


