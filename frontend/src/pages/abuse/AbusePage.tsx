import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Alert,
  Button,
  ConfigProvider,
  Input,
  Layout,
  Modal,
  Radio,
  Select,
  Space,
  Spin,
  Table,
  Tag,
  Typography,
  message,
} from 'antd';
import { ReloadOutlined, StopOutlined, UnlockOutlined } from '@ant-design/icons';

import AppSidebar from '@/layouts/AppSidebar';
import { useTheme } from '@/hooks/useTheme';
import { HttpUtil } from '@/utils';
import { Sparkline } from '@/components/viz';
import { setMessageInstance } from '@/utils/messageBus';
import './AbusePage.css';

type Account = {
  email: string;
  connections: number;
  blocked: number;
  sourceIps: number;
  lastSeen: number;
  windowUp: number;
  windowDown: number;
};
type Source = { ip: string; users: string; connections: number; lastSeen: number };
type Port = { network: string; port: number; connections: number };
type Summary = {
  logEnabled: boolean;
  statsEnabled: boolean;
  connections: number;
  blocked: number;
  accounts: Account[];
  sources: Source[];
  ports: Port[];
};
type Bans = { available: boolean; jail: string; ips: string[] };
type Point = { second: number; upMbps: number; downMbps: number };

function bytes(value: number) {
  if (value < 1024) return `${value} B`;
  const unit = Math.min(4, Math.floor(Math.log(value) / Math.log(1024)));
  return `${(value / 1024 ** unit).toFixed(2)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit]}`;
}

export default function AbusePage() {
  const { t } = useTranslation();
  const { antdThemeConfig } = useTheme();
  const [messageApi, messageHolder] = message.useMessage();
  const [modal, modalHolder] = Modal.useModal();
  const [hours, setHours] = useState(24);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [bans, setBans] = useState<Bans | null>(null);
  const [email, setEmail] = useState('');
  const [points, setPoints] = useState<Point[]>([]);
  const [ip, setIP] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => setMessageInstance(messageApi), [messageApi]);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [stats, blocked] = await Promise.all([
        HttpUtil.get<Summary>('/panel/api/abuse/summary', { hours }, { silent: true }),
        HttpUtil.get<Bans>('/panel/api/abuse/bans', undefined, { silent: true }),
      ]);
      if (!stats.success) messageApi.error(stats.msg);
      if (!blocked.success) messageApi.error(blocked.msg);
      if (stats.success && stats.obj) {
        setSummary(stats.obj);
        setEmail((current) => current || stats.obj?.accounts[0]?.email || '');
      }
      if (blocked.success && blocked.obj) setBans(blocked.obj);
    } finally {
      setLoading(false);
    }
  }, [hours, messageApi]);

  useEffect(() => {
    const first = window.setTimeout(() => void refresh(), 0);
    const timer = window.setInterval(() => void refresh(), 30000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [refresh]);

  useEffect(() => {
    if (!email) return;
    const load = async () => {
      const result = await HttpUtil.get<Point[]>(
        '/panel/api/abuse/bandwidth',
        { email },
        { silent: true },
      );
      if (result.success && result.obj) setPoints(result.obj);
    };
    void load();
    const timer = window.setInterval(() => void load(), 10000);
    return () => window.clearInterval(timer);
  }, [email]);

  const setBan = (target: string, ban: boolean) => {
    modal.confirm({
      title: t(ban ? 'pages.abuse.confirmBan' : 'pages.abuse.confirmUnban', { ip: target }),
      okType: ban ? 'danger' : 'primary',
      onOk: async () => {
        const result = await HttpUtil.post(`/panel/api/abuse/${ban ? 'ban' : 'unban'}`, {
          ip: target,
        });
        if (!result.success) throw new Error(result.msg);
        setIP('');
        await refresh();
      },
    });
  };

  const accountColumns = [
    { title: t('pages.abuse.account'), dataIndex: 'email', key: 'email' },
    { title: t('pages.abuse.upload'), dataIndex: 'windowUp', key: 'up', render: bytes },
    { title: t('pages.abuse.download'), dataIndex: 'windowDown', key: 'down', render: bytes },
    { title: t('pages.abuse.connections'), dataIndex: 'connections', key: 'connections' },
    { title: t('pages.abuse.blocked'), dataIndex: 'blocked', key: 'blocked' },
    { title: t('pages.abuse.sourceIPs'), dataIndex: 'sourceIps', key: 'sourceIps' },
  ];

  return (
    <ConfigProvider theme={antdThemeConfig}>
      {messageHolder}
      {modalHolder}
      <Layout className="abuse-layout">
        <AppSidebar />
        <Layout className="content-shell">
          <Layout.Content id="content-layout" className="content-area abuse-content">
            <div className="abuse-header">
              <Typography.Title level={3}>{t('menu.abuse')}</Typography.Title>
              <Space wrap>
                <Radio.Group
                  value={hours}
                  onChange={(event) => setHours(event.target.value)}
                  options={[
                    { label: '24h', value: 24 },
                    { label: '7d', value: 168 },
                  ]}
                  optionType="button"
                />
                <Button
                  icon={<ReloadOutlined aria-hidden />}
                  title={t('refresh')}
                  onClick={() => void refresh()}
                />
              </Space>
            </div>
            <Spin spinning={loading && !summary}>
              {summary && !summary.logEnabled && (
                <Alert type="warning" showIcon message={t('pages.abuse.logOff')} />
              )}
              {summary?.logEnabled && !summary.statsEnabled && (
                <Alert type="info" showIcon message={t('pages.abuse.statsOff')} />
              )}
              {summary?.statsEnabled && (
                <>
                  <div className="abuse-metrics">
                    <div>
                      <span>{t('pages.abuse.connections')}</span>
                      <strong>{summary.connections.toLocaleString()}</strong>
                    </div>
                    <div>
                      <span>{t('pages.abuse.blocked')}</span>
                      <strong>{summary.blocked.toLocaleString()}</strong>
                    </div>
                    <div>
                      <span>{t('pages.abuse.accounts')}</span>
                      <strong>{summary.accounts.length}</strong>
                    </div>
                  </div>
                  <section className="abuse-section">
                    <Typography.Title level={5}>{t('pages.abuse.accounts')}</Typography.Title>
                    <Table
                      rowKey="email"
                      size="small"
                      pagination={{ pageSize: 10 }}
                      scroll={{ x: 720 }}
                      dataSource={summary.accounts}
                      columns={accountColumns}
                      onRow={(row) => ({
                        onClick: () => setEmail(row.email),
                        className: row.email === email ? 'abuse-selected' : '',
                      })}
                    />
                  </section>
                  <section className="abuse-section">
                    <div className="abuse-section-header">
                      <Typography.Title level={5}>{t('pages.abuse.bandwidth')}</Typography.Title>
                      <Select
                        aria-label={t('pages.abuse.account')}
                        value={email || undefined}
                        style={{ minWidth: 180 }}
                        options={summary.accounts.map((account) => ({
                          value: account.email,
                          label: account.email,
                        }))}
                        onChange={setEmail}
                      />
                    </div>
                    <Sparkline
                      data={points.map((point) => point.downMbps)}
                      data2={points.map((point) => point.upMbps)}
                      labels={points.map((point) =>
                        new Date(point.second * 1000).toLocaleTimeString(),
                      )}
                      name1={t('pages.abuse.download')}
                      name2={t('pages.abuse.upload')}
                      height={220}
                      maxPoints={720}
                      showAxes
                      showGrid
                      showTooltip
                      showLegend
                      yFormatter={(value) => `${value.toFixed(1)} Mbps`}
                      tooltipFormatter={(value) => `${value.toFixed(2)} Mbps`}
                    />
                    <Typography.Text type="secondary">
                      {t('pages.abuse.bandwidthHint')}
                    </Typography.Text>
                  </section>
                  <section className="abuse-section">
                    <Typography.Title level={5}>{t('pages.abuse.sourceIPs')}</Typography.Title>
                    <Table
                      rowKey="ip"
                      size="small"
                      pagination={{ pageSize: 10 }}
                      scroll={{ x: 620 }}
                      dataSource={summary.sources}
                      columns={[
                        { title: 'IP', dataIndex: 'ip' },
                        { title: t('pages.abuse.accounts'), dataIndex: 'users' },
                        { title: t('pages.abuse.connections'), dataIndex: 'connections' },
                        {
                          title: '',
                          key: 'action',
                          render: (_: unknown, row: Source) => (
                            <Button
                              icon={<StopOutlined aria-hidden />}
                              title={t('pages.abuse.ban')}
                              size="small"
                              disabled={!bans?.available || bans.ips.includes(row.ip)}
                              onClick={() => setBan(row.ip, true)}
                            />
                          ),
                        },
                      ]}
                    />
                  </section>
                  <section className="abuse-section">
                    <Typography.Title level={5}>{t('pages.abuse.ports')}</Typography.Title>
                    <Space wrap>
                      {summary.ports.map((port) => (
                        <Tag key={`${port.network}:${port.port}`}>
                          {port.network.toUpperCase()} {port.port}: {port.connections}
                        </Tag>
                      ))}
                    </Space>
                  </section>
                </>
              )}
              <section className="abuse-section">
                <Typography.Title level={5}>{t('pages.abuse.bans')}</Typography.Title>
                {!bans?.available ? (
                  <Alert type="warning" showIcon message={t('pages.abuse.bansUnavailable')} />
                ) : (
                  <>
                    <Space.Compact className="abuse-ban-input">
                      <Input
                        aria-label="IP"
                        value={ip}
                        placeholder="IPv4 / IPv6"
                        onChange={(event) => setIP(event.target.value)}
                      />
                      <Button
                        danger
                        icon={<StopOutlined aria-hidden />}
                        disabled={!ip.trim()}
                        onClick={() => setBan(ip.trim(), true)}
                      >
                        {t('pages.abuse.ban')}
                      </Button>
                    </Space.Compact>
                    <div className="abuse-bans">
                      {bans.ips.map((address) => (
                        <Tag key={address} closable={false}>
                          {address}{' '}
                          <Button
                            size="small"
                            type="text"
                            icon={<UnlockOutlined aria-hidden />}
                            title={t('pages.abuse.unban')}
                            onClick={() => setBan(address, false)}
                          />
                        </Tag>
                      ))}
                    </div>
                  </>
                )}
              </section>
            </Spin>
          </Layout.Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  );
}
