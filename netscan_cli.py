#!/usr/bin/python3
import click
from scapy.sendrecv import sniff

from net_discover import icmp_scan, arp2_monitor_callback
import orm
import settings


@click.group()
def cli():
    pass


@cli.command()
def view():
    """Visualização dos dispositivos conhecidos na rede"""
    click.echo(orm.get_devices())


@cli.command()
@click.option('--timeout', default=1, help='Time to consider a ICMP response as timeout')
@click.option('--ip', default='192.168.0.100/28', help='IP range to send packets')
def icmp(ip, timeout):
    """Procedimento de descoberta de rede via mensagens icmp"""
    icmp_scan(ip_dst=ip, timeout=timeout)
    orm.get_line_device.cache_clear()


@cli.command()
@click.option('--timeout', default=1, help='Time to consider a ICMP response as timeout')
def arp_response(timeout):
    """Descoberta da rede por meio de escuta de respostas arp (considera somente campos source)"""
    settings.set_setting("arp2_run", True)
    sniff(prn=arp2_monitor_callback, filter="arp", store=0, timeout=timeout)
    settings.set_setting("arp2_run", False)
    orm.get_line_device.cache_clear()

@cli.command()
@click.argument("mac_address")
def history(mac_address):
    """Histórico de informações obtidas de um disposítivo"""
    click.echo(orm.history_device(mac_address))


@cli.command()
def clear():
    """Deleta todos os registros de dispositivos e descobertas"""
    orm.drop_devices()
    orm.get_line_history.cache_clear()
    orm.get_line_device.cache_clear()


if __name__ == '__main__':
    cli()
