package org.mule.routing.filters.antivirus.spi.clamav;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Iterator;

import org.mule.routing.filters.antivirus.spi.AbstractTCPBasedScannerProvider;

public class ClamAVTCPScannerProvider extends AbstractTCPBasedScannerProvider
{

    void setPort(final int port)
    {
        this.port = port;
    }

    @Override
    protected void initSocket(final Socket s) throws IOException

    {
        final OutputStream out = s.getOutputStream();
        final BufferedReader d = new BufferedReader(new InputStreamReader(s
                .getInputStream()));

        write("SESSION", out);

        if (version == null)
        {
            version = writeAndRead("VERSION", out, d);

            logger.debug("set version to " + version);
        }

        if (props != null)
        {
            final Iterator it = props.keySet().iterator();

            while (it.hasNext())
            {
                final String key = (String) it.next();

                if (!key.startsWith("clamav.tcp.optional."))
                {
                    continue;

                }

                final String cmd = "SET "
                        + key.substring("clamav.tcp.optional.".length()) + " "
                        + props.getProperty(key);

                writeAndRead(cmd.toUpperCase(), out, d);

            }
        }

    }

    @Override
    protected boolean isError(final String lastAnswer)
    {
        if ((lastAnswer == null) || (lastAnswer.length() == 0)
                || (lastAnswer.indexOf("ERROR") != -1)
                || (lastAnswer.indexOf("UNKNOWN") != -1))
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    @Override
    protected String fillAnswer(final BufferedReader d) throws IOException
    {

        final String lastAnswer = d.readLine();
        return lastAnswer;
    }

    @Override
    protected boolean isVirus(final String lastAnswer)
    {
        if (lastAnswer.indexOf("FOUND") != -1)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    public String getName()
    {
        // TODO Auto-generated method stub
        return "CLAMAV";
    }

    @Override
    protected String getScanCommand(final File file)
    {
        // TODO Auto-generated method stub
        return "CONTSCAN " + file.getAbsolutePath();
    }

}
