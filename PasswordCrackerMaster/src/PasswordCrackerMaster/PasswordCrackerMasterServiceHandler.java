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
import java.util.Vector;
import java.util.concurrent.*;

import static PasswordCrackerMaster.PasswordCrackerConts.WORKER_PORT;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.jobInfoMap;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.activeJobs;
import static PasswordCrackerMaster.PasswordCrackerMasterServiceHandler.workersAddressList;

public class PasswordCrackerMasterServiceHandler implements PasswordCrackerMasterService.Iface {
    public static List<TSocket> workersSocketList = new LinkedList<>();  //Connected Socket
    public static List<String> workersAddressList = new LinkedList<>(); // Connected WorkerAddress
    public static ConcurrentHashMap<String, PasswordDecrypterJob> jobInfoMap = new ConcurrentHashMap<>(); // <ecrpytedPassword=jobid, FuturePassword>
    public static ConcurrentHashMap<String, Long> latestHeartbeatInMillis = new ConcurrentHashMap<>(); // <workerAddress, time>
    public static ExecutorService workerPool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors() * 2);
    public static ScheduledExecutorService heartBeatCheckPool = Executors.newScheduledThreadPool(1);
    public static Vector<JobInfo> activeJobs = new Vector<>(); // <worker address, job information>


    /*
     * Class to track job information of worker
     */
    static class JobInfo {

        private String workerAddress;
        private long rangeBegin;
        private long rangeSize;
        private String encryptedPassword;

        JobInfo(String workerAddress, long rangeBegin, long rangeSize, String encryptedPassword) {
            this.workerAddress = workerAddress;
            this.rangeBegin = rangeBegin;
            this.rangeSize = rangeSize;
            this.encryptedPassword = encryptedPassword;
        }

        public String getWorkerAddress() {
            return workerAddress;
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
        System.out.println("INFO: New job " + encryptedPassword);
        PasswordDecrypterJob decryptJob = jobInfoMap.get(encryptedPassword);
        if (decryptJob == null) {
            System.out.println("INFO: Starting new computation");
            decryptJob = new PasswordDecrypterJob();
            jobInfoMap.put(encryptedPassword, decryptJob);
            workerPool.submit(() ->
                    requestFindPassword(encryptedPassword, 0, PasswordCrackerConts.TOTAL_PASSWORD_RANGE_SIZE));
        } else {
            System.out.println("INFO: Retrieving from cached data");
        }
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
    public static void requestFindPassword(String encryptedPassword, long rangeBegin, long rangeSize) {
        PasswordCrackerWorkerService.AsyncClient worker;
        FindPasswordMethodCallback findPasswordCallBack = new FindPasswordMethodCallback(encryptedPassword);
        try {
            int workerId = 0;
            for (String workerAddress : workersAddressList) {
                long subRangeSize = (rangeSize + workersAddressList.size() - 1) / workersAddressList.size();
                long subRangeBegin = rangeBegin + (workerId * subRangeSize);
                long subRangeEnd = subRangeBegin + subRangeSize;
                JobInfo jobInfo = new JobInfo(workerAddress, subRangeBegin, subRangeSize, encryptedPassword);
                activeJobs.add(jobInfo);

                worker = new PasswordCrackerWorkerService.AsyncClient(new TBinaryProtocol.Factory(), new TAsyncClientManager(), new TNonblockingSocket(workerAddress, WORKER_PORT));
                worker.startFindPasswordInRange(subRangeBegin, subRangeEnd, encryptedPassword, findPasswordCallBack);
                System.out.println("INFO: sending job to " + workerAddress + " range " + subRangeBegin + " - " + subRangeEnd + " password " + encryptedPassword);
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
        ArrayList<JobInfo> redistributionJobs = new ArrayList<>();
        activeJobs.forEach((JobInfo jobInfo) -> {
            failedWorkerIdList.forEach((String workerAddress) -> {
                        if (jobInfo.getWorkerAddress().equals(workerAddress)) {
                            System.out.println("INFO: redistributing job;" +
                                    " [address] " + workerAddress +
                                    " [password] " + jobInfo.getEncryptedPassword() +
                                    " [range] " + jobInfo.getRangeBegin() +
                                    " [size] " + jobInfo.getRangeSize());
                            redistributionJobs.add(jobInfo);
                            activeJobs.remove(jobInfo);
                        }
                    });
                });
        redistributionJobs.forEach((JobInfo jobInfo) -> {
            workerPool.submit(() ->
                    requestFindPassword(jobInfo.getEncryptedPassword(), jobInfo.getRangeBegin(), jobInfo.getRangeSize()));
        });
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
                System.out.println("INFO: failed worker " + node);
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
                System.out.println("INFO: Job finished " + jobId);
                activeJobs.removeIf(jobInfo -> jobInfo.getEncryptedPassword().equals(jobId));
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
            PasswordCrackerWorkerService.AsyncClient worker;
            for (String workerAddress : workersAddressList) {
                worker = new PasswordCrackerWorkerService.AsyncClient(
                        new TBinaryProtocol.Factory(),
                        new TAsyncClientManager(),
                        new TNonblockingSocket(workerAddress, WORKER_PORT));
                /** COMPLETE **/
                System.out.println("INFO: terminating job " + jobId + " on " + workerAddress);
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
