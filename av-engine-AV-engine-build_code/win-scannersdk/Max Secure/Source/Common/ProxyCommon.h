#define MAX_CLIENT_COMMAND_SIZE 50
#define MAX_MAIL_SIZE	10240000
#define STOP_BOTH	0x02

const char szPROXY_MAIL_HEADER_POP3[] = "{799539E5-EDCE-4565-9A62-1E957F0A0F84}-POP3\r\n";
const char szPROXY_MAIL_HEADER_SMTP[] = "{799539E5-EDCE-4565-9A62-1E957F0A0F84}-SMTP\r\n";
const DWORD dwHDR_POP3_LENGTH = 45;
const DWORD dwHDR_SMTP_LENGTH = 45;

const char DELETED_MAIL_RESPONSE[] = "+OK 237 octets\r\nFrom: Scanner@Aura\r\nSubject: Mail Deleted\r\nTo: Scanner@Aura\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=us-ascii\r\n\r\nAura Mail Scanner Deleted the infected mail\r\n\r\n.\r\n";
const char FAKE_MAIL_HEADER[] = "+OK TimeOut octects\r\n";
const char FAKE_MAIL_HEADER1[] = "X-Priority: 3\r\n";
const char DELETED_MAIL_RESPONSE_SMTP[] = "MAIL CONTAINED BAD ATTACHMENTS, HENCE DELETD, PLEASE DELETE THE MAIL FROM OUTBOX AND RESEND AGAIN\r\n";
