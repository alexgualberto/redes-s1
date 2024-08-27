from iputils import *
import ipaddress

class CIDR:
    def __init__(self, cidr):
        self.address, self.n = tuple(cidr.split('/'))
        self.n = int(self.n)
        self.prefix = int.from_bytes(str2addr(self.address), 'big') >> 32 - self.n

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None
        self.id = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            next_hop = self._next_hop(dst_addr)
            ttl -= 1
            if (ttl == 0):
                checksum = calc_checksum(struct.pack('>BBHI', 11, 0, 0, 0) + datagrama[:28])
                self.enviar((struct.pack('>BBHI', 11, 0, 0, checksum) + datagrama[:28]), src_addr, 1)
                return

            cabecalho = struct.pack('>BBHHHBBH', 0x45, dscp | ecn, (20 + len(payload)), identification,  (flags << 13) | frag_offset, ttl, proto, 0)
            cabecalho += str2addr(src_addr) +str2addr(dst_addr)

            cabecalho_final = struct.pack('>BBHHHBBH', 0x45, 0, (20 + len(payload)), identification,  (flags << 13) | frag_offset, ttl, proto, calc_checksum(cabecalho))

            cabecalho_final += str2addr(src_addr) +str2addr(dst_addr)

            datagrama = cabecalho_final + payload

            self.enlace.enviar(datagrama, next_hop)

    def _next_hop(self, dest_addr):
        next_hop = None
        max_n = -1
        for cidr in self.tabela:
            if int.from_bytes(str2addr(dest_addr), 'big') >> 32 - cidr.n == cidr.prefix:
                if cidr.n > max_n:
                    next_hop = self.tabela[cidr]
                    max_n = cidr.n
        return next_hop


    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        self.tabela = {}
        for x in tabela:
            cidr, next_hop = x
            self.tabela[CIDR(cidr)] = next_hop


    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr, protocolo = 6):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)

        cabecalho = struct.pack('>BBHHHBBH', 0x45, 0, (20 + len(segmento)), self.id,  0, 64, protocolo, 0)
        cabecalho += str2addr(self.meu_endereco) +str2addr(dest_addr)

        cabecalho_final = struct.pack('>BBHHHBBH', 0x45, 0, (20 + len(segmento)), self.id,  0, 64, protocolo, calc_checksum(cabecalho))

        cabecalho_final += str2addr(self.meu_endereco) +str2addr(dest_addr)

        self.id += 1

        datagrama = cabecalho_final + segmento

        self.enlace.enviar(datagrama, next_hop)
