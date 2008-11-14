package org.mule.routing.filters.antivirus.spi;

public class ScannerException extends Exception
{

    /**
     * 
     */
    private static final long serialVersionUID = 1L;

    public ScannerException(final String message, final Throwable cause)
    {
        super(message, cause);
        // TODO Auto-generated constructor stub
    }

    public ScannerException(final String message)
    {
        super(message);
        // TODO Auto-generated constructor stub
    }

    public ScannerException(final Throwable cause)
    {
        super(cause);
        // TODO Auto-generated constructor stub
    }

}
