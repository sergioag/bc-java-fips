package org.bouncycastle.jcajce.provider;

import java.util.concurrent.ConcurrentLinkedDeque;

class EntropyDaemon
    implements Runnable
{
    private final ConcurrentLinkedDeque<Runnable> tasks = new ConcurrentLinkedDeque<Runnable>();

    void addTask(Runnable task)
    {
        tasks.add(task);
    }

    @Override
    public void run()
    {
        while (!Thread.currentThread().isInterrupted())
        {
            Runnable task = tasks.pollFirst();

            if (task != null)
            {
                try
                {
                    task.run();
                }
                catch (Throwable e)
                {
                    // ignore
                }
            }
            else
            {
                try
                {
                    Thread.sleep(5000);
                }
                catch (InterruptedException e)
                {
                    Thread.currentThread().interrupt();
                }
            }
        }
    }
}
