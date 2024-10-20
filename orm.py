# Generated by ChatGPT, version October 2024, on 2024-10-17

from sqlalchemy import create_engine, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, mapped_column, Mapped, relationship, Session
from datetime import datetime
from sqlalchemy import select
from vendor_solver import vendor_solver

# Define o modelo base
Base = declarative_base()


# Define a tabela Device como um modelo
class Device(Base):
    __tablename__ = 'devices'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    mac_addr: Mapped[str] = mapped_column(String, nullable=False)
    gateway: Mapped[bool] = mapped_column(Boolean, nullable=False)

    # Relação com DeviceNetwork (um Device pode ter várias entradas em DeviceNetwork)
    networks = relationship("DeviceNetwork", back_populates="device", foreign_keys="DeviceNetwork.device_id")

    def __repr__(self):
        return f"<Device(id={self.id}, mac_addr='{self.mac_addr}', gateway={self.gateway})>"


# Define a tabela DiscoveryMethod como um modelo
class DiscoveryMethod(Base):
    __tablename__ = 'discovery_method'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    method: Mapped[str] = mapped_column(String, nullable=False)

    # Relação com DeviceNetwork
    networks = relationship("DeviceNetwork", back_populates="discovery_method")

    def __repr__(self):
        return f"<DiscoveryMethod(id={self.id}, method='{self.method}')>"


# Define a tabela DeviceNetwork como um modelo
class DeviceNetwork(Base):
    __tablename__ = 'device_networks'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Chave estrangeira para a tabela Device (dispositivo)
    device_id: Mapped[int] = mapped_column(ForeignKey('devices.id'), nullable=False)
    device = relationship("Device", back_populates="networks", foreign_keys=[device_id])

    # Chave estrangeira para o gateway (que também é um Device)
    gateway_id: Mapped[int] = mapped_column(ForeignKey('devices.id'), nullable=False)
    gateway = relationship("Device", foreign_keys=[gateway_id])

    # Chave estrangeira para o método de descoberta
    discovery_method_id: Mapped[int] = mapped_column(ForeignKey('discovery_method.id'))
    discovery_method = relationship("DiscoveryMethod", back_populates="networks")

    ip: Mapped[str] = mapped_column(String, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    discovered_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    def __repr__(self):
        return f"<DeviceNetwork(id={self.id}, ip='{self.ip}', last_seen_at={self.last_seen_at})>"

    def __str__(self):
        return (f"mac: {self.device.mac_addr} | vendor: {vendor_solver(self.device.mac_addr[0:9])} | "
                f"ip: {self.device.ip} | dicovered: {self.discovered_at} | gateway: {self.gateway}")


# Cria a engine SQLite
engine = create_engine('sqlite:///network_discovery.db')
Base.metadata.create_all(engine)



def save(ip: str, mac: str):
    with engine.connect() as connection:
        with Session(bind=connection) as session:
            pass
            # 1 - Verificar se o mac address corresponde ao gateway
            # 2- Ver se o dispositivo já está cadastrado
                # Caso necessário cadastre
            # 3 - Cadastrá-lo
            # 

