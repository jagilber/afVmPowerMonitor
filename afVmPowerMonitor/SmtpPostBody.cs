namespace afVmPowerMonitor
{
    public class SmtpPostBody
    {
        public Message message = new Message();

        public class Message
        {
            public string subject;
            public Body body = new Body();
            public ToRecipients[] toRecipients; //= new ToRecipients[1];

            public class Body
            {
                public string contentType;
                public string content;
            }

            public class ToRecipients
            {
                public EmailAddress emailAddress = new EmailAddress();

                public class EmailAddress
                {
                    public string address;
                }
            }
        }
    }
}