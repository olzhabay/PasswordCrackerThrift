package PasswordCrackerMaster;

import org.apache.thrift.TException;
import org.apache.thrift.async.AsyncMethodCallback;
import org.apache.thrift.async.TAsyncClientManager;
import org.apache.thrift.protocol.TBinaryProtocol;
import org.apache.thrift.transport.TNonblockingSocket;
import org.apache.thrift.transport.TSocket;
import thrift.gen.PasswordCrackerMasterService.PasswordCrackerMasterService;
import thrift.gen.PasswordCrackerWorkerService.PasswordCrackerWorkerService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.*;

import static PasswordCrackerMaster.PasswordCrackerConts.WORKER_PORT;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.jobInfoMap;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.workersAddressList;

public class PasswordCrackerMasterServiceHandler implements PasswordCrackerMasterService.Iface {
    public static List<TSocket> workersSocketList = new LinkedList<>();  //Connected Socket
    public static List<String> workersAddressList = new LinkedList<>(); // Connected WorkerAddress
    public static ConcurrentHashMap<String, PasswordDecrypterJob> jobInfoMap = new ConcurrentHashMap<>(); // <ecrpytedPassword=jobid, FuturePassword>
    public static ConcurrentHashMap<String, Long> latestHeartbeatInMillis = new ConcurrentHashMap<>(); // <workerAddress, time>
    public static ExecutorService workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
    public static ScheduledExecutorService heartBeatCheckPool = Executors.newScheduledThreadPool(1);
    public static ConcurrentHashMap<String, JobInfo> workersRange = new ConcurrentHashMap<>(); // <worker address, job information>


    /*
     * Class to track job information of worker
     */
    static class JobInfo {

        private long rangeBegin;
        private long rangeSize;
        private String encryptedPassword;

        JobInfo(long rangeBegin, long rangeSize, String encryptedPassword) {
            this.rangeBegin = rangeBegin;
            this.rangeSize = rangeSize;
            this.encryptedPassword = encryptedPassword;
        }

        public long getRangeBegin() {
            return rangeBegin;
        }

        public long getRangeSize() {
            return rangeSize;
        }

        public String getEncryptedPassword() {
            return encryptedPassword;
        }
    }

    /*
     * The decrypt method create the job and put the job with jobId (encrypted Password) in map.
     * And call the requestFindPassword and if it finds the password, it return the password to the client.
     */
    @Override
    public String decrypt(String encryptedPassword)
            throws TException {
        PasswordDecrypterJob decryptJob = new PasswordDecrypterJob();
        jobInfoMap.put(encryptedPassword, decryptJob);
        /** COMPLETE **/
        workerPool.submit(() ->
                requestFindPassword(encryptedPassword, 0, PasswordCrackerConts.TOTAL_PASSWORD_RANGE_SIZE));
        try {
            return decryptJob.getPassword();
        } catch (ExecutionException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return null;
    }



    /*
     * The reportHeartBeat receives the heartBeat from workers.
     * Consider the checkHeartBeat method and use latestHeartbeatInMillis map.
    */
    @Override
    public void reportHeartBeat(String workerAddress) throws TException {
        /** COMPLETE **/
        latestHeartbeatInMillis.put(workerAddress, System.currentTimeMillis());
    }

    /*
     * The requestFindPassword requests workers to find password using RPC in asynchronous way.
    */
    public static void requestFindPassword(String encryptedPassword, long rangeBegin, long subRangeSize) {
        PasswordCrackerWorkerService.AsyncClient worker;
        FindPasswordMethodCallback findPasswordCallBack = new FindPasswordMethodCallback(encryptedPassword);
        try {
            int workerId = 0;
            for (String workerAddress : workersAddressList) {

                long subRangeBegin = rangeBegin + (workerId * subRangeSize);
                long subRangeEnd = subRangeBegin + subRangeSize;
                JobInfo range = new JobInfo(subRangeBegin, subRangeSize, encryptedPassword);
                workersRange.put(workerAddress, range);

                worker = new PasswordCrackerWorkerService.AsyncClient(new TBinaryProtocol.Factory(), new TAsyncClientManager(), new TNonblockingSocket(workerAddress, WORKER_PORT));
                worker.startFindPasswordInRange(subRangeBegin, subRangeEnd, encryptedPassword, findPasswordCallBack);
                workerId++;
            }
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        catch (TException e) {
            e.printStackTrace();
        }
    }

    /*
     * The redistributeFailedTask distributes the dead workers's job (or a set of possible password) to active workers.
     *
     * Check the checkHeartBeat method
     */
    public static void redistributeFailedTask(ArrayList<String> failedWorkerIdList) {
        /** COMPLETE **/
        ArrayList<JobInfo> redistributionRanges = new ArrayList<>();
        for (String workerAddress:failedWorkerIdList) {
            redistributionRanges.add(workersRange.get(workerAddress));
            workersAddressList.remove(workerAddress);
            workersRange.remove(workerAddress);
        }
        redistributionRanges.forEach((JobInfo job) ->
                workerPool.submit(() ->
                        requestFindPassword(job.getEncryptedPassword(), job.getRangeBegin(), job.getRangeSize())));
    }

    /*
     *  If the master didn't receive the "HeartBeat" in 5 seconds from any workers,
     *  it considers the workers that didn't send the "HeartBeat" as dead.
     *  And then, it redistributes the dead workers's job in other alive workers
     *
     *  hint : use latestHeartbeatinMillis, workerAddressList
     *
     *  you must think about when several workers is dead.
     *
     *  and use the workerPool
     */
    public static void checkHeartBeat() {
        /** COMPLETE **/
        final long thresholdAge = 5_000;
        ArrayList<String> failedWorkerIdList = new ArrayList<>();
        latestHeartbeatInMillis.forEach((String node, Long time) -> {
            if (System.currentTimeMillis() - time > thresholdAge) {
                failedWorkerIdList.add(node);
            }
        });
        if (!failedWorkerIdList.isEmpty()) {
            redistributeFailedTask(failedWorkerIdList);
        }
    }
}

//CallBack
class FindPasswordMethodCallback implements
        AsyncMethodCallback<PasswordCrackerWorkerService.AsyncClient.startFindPasswordInRange_call> {
    private String jobId;

    FindPasswordMethodCallback(String jobId) {
        this.jobId = jobId;
    }

    /*
     *  if the returned result from worker is not null, it completes the job.
     *  and call the jobTermination method
     */
    @Override
    public void onComplete(PasswordCrackerWorkerService.AsyncClient.startFindPasswordInRange_call startFindPasswordInRange_call) {
        try {
            String findPasswordResult = startFindPasswordInRange_call.getResult();
            /** COMPLETE **/
            if (findPasswordResult != null) {
                jobInfoMap.get(jobId).setPassword(findPasswordResult);
                jobTermination(jobId);
            }
        }
        catch (TException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onError(Exception e) {
        System.out.println("Error : startFindPasswordInRange of FindPasswordMethodCallback");
    }

    /*
     *  The jobTermination transfer the termination signal to workers in asynchronous way
     */
    private void jobTermination(String jobId) {
        try {
            PasswordCrackerWorkerService.AsyncClient worker = null;
            for (String workerAddress : workersAddressList) {
                worker = new PasswordCrackerWorkerService.AsyncClient(
                        new TBinaryProtocol.Factory(),
                        new TAsyncClientManager(),
                        new TNonblockingSocket(workerAddress, WORKER_PORT));
                /** COMPLETE **/
                worker.reportTermination(jobId, this);
            }
        }
        catch (TException e) {
            e.printStackTrace();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
    }
}
