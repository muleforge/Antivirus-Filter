package org.mule.routing.filters.antivirus.spi;

public class VirusFoundException extends Exception
{

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public VirusFoundException(final String message, final Throwable cause)
    {
        super(message, cause);
        // TODO Auto-generated constructor stub
    }

    public VirusFoundException(final String message)
    {
        super(message);
        // TODO Auto-generated constructor stub
    }

    public VirusFoundException(final Throwable cause)
    {
        super(cause);
        // TODO Auto-generated constructor stub
    }

}
