import unittest

from mock import MagicMock, patch, call
from sqlalchemy.orm import Query

from bounded_contexts.central_console.domain_services.abstract_platform_repository import AbstractPlatformRepository
from bounded_contexts.central_console.models.platform import Platform
from bounded_contexts.central_console.models.sensor import Sensor
from infrastructure.bounded_contexts.central_console.domain_services.abstract_sensor_repository import \
    alchemy_sensor_repository
from unit_tests.alchemy_test_case import AlchemyTestCase


class TestAlchemySensorRepository(AlchemyTestCase):

    def setUp(self):
        self.setup_require_db_decorator_mock(alchemy_sensor_repository)

        self.platform_repo = MagicMock(spec=AbstractPlatformRepository)
        self.sensor_constructor = Sensor
        self.repo = alchemy_sensor_repository.AlchemySensorRepository(self.sensor_constructor, self.platform_repo)

    """
    def test_get_sensors_decorated(self):
        self.assert_require_db_decorated(
            alchemy_sensor_repository.AlchemySensorRepository.get_sensors.__func__
        )

    
    @patch.object(alchemy_sensor_repository, 'Sensor', autospec=True)
    @patch('db.session', autospec=True)
    def test_get_sensors(self, session_mock, alchemy_sensor_mock):
        session_mock.query.return_value = query_mock = MagicMock(spec=Query)
        alchemy_sensor_count = 2
        query_mock.all.return_value = [
            MagicMock(spec=alchemy_sensor_repository.Sensor) for _ in xrange(alchemy_sensor_count)
        ]
        self.repo._AlchemySensorRepository__build_sensor_from_alchemy_object = MagicMock()
        self.repo._AlchemySensorRepository__build_sensor_from_alchemy_object.side_effect = expected_sensors = [
            MagicMock(spec=Sensor) for _ in xrange(alchemy_sensor_count)
        ]

        actual_sensors = self.repo.get_sensors()

        session_mock.query.assert_called_once_with(alchemy_sensor_mock)
        query_mock.all.assert_called_once_with()
        self.repo._AlchemySensorRepository__build_sensor_from_alchemy_object.assert_has_calls([
            call(alchemy_sensor) for alchemy_sensor in query_mock.all.return_value
        ])
        self.assertEqual(actual_sensors, expected_sensors)


    @patch.object(alchemy_sensor_repository, 'get_uuid_string_from_bytes', autospec=True)
    @patch.object(alchemy_sensor_repository, 'get_sensor_ip_from_sensor_id', autospec=True)
    def test_build_sensor_from_alchemy_object_connected(self, get_ip_from_id_mock, get_uuid_string_from_bytes_mock):
        alchemy_object = MagicMock(spec=alchemy_sensor_repository.Sensor)
        expected_sensor_ip = MagicMock(name='sensor_ip')
        get_ip_from_id_mock.return_value = (True, expected_sensor_ip)
        self.platform_repo.get_platform.return_value = sensor_platform = MagicMock(spec=Platform)
        self.set_named_tuple_mock_bool_context_value(sensor_platform, True)
        get_software_version_mock = self.repo._AlchemySensorRepository__get_software_version = MagicMock()
        expected_sensor = self.sensor_constructor(
            get_uuid_string_from_bytes_mock.return_value,
            alchemy_object.name,
            alchemy_object.descr,
            sensor_platform.name,
            expected_sensor_ip,
            get_software_version_mock.return_value,
            sensor_platform.threat_intelligence_version,
            self.platform_repo.get_platform.return_value is not None
        )

        actual_sensor = self.repo._AlchemySensorRepository__build_sensor_from_alchemy_object(alchemy_object)

        get_uuid_string_from_bytes_mock.assert_called_once_with(alchemy_object.id)
        get_ip_from_id_mock.assert_called_once_with(get_uuid_string_from_bytes_mock.return_value)
        self.platform_repo.get_platform.assert_called_once_with(expected_sensor_ip)
        get_software_version_mock.assert_called_once_with(alchemy_object.id)
        self.assertEqual(actual_sensor, expected_sensor)

    @patch.object(alchemy_sensor_repository, 'get_uuid_string_from_bytes', autospec=True)
    @patch.object(alchemy_sensor_repository, 'get_sensor_ip_from_sensor_id', autospec=True)
    def test_build_sensor_from_alchemy_object_disconnected(
            self,
            get_ip_from_id_mock,
            get_uuid_string_from_bytes_mock
    ):
        alchemy_object = MagicMock(spec=alchemy_sensor_repository.Sensor)
        expected_sensor_ip = MagicMock(name='sensor_ip')
        get_ip_from_id_mock.return_value = (True, expected_sensor_ip)
        self.platform_repo.get_platform.return_value = None
        get_software_version_mock = self.repo._AlchemySensorRepository__get_software_version = MagicMock()
        expected_sensor = self.sensor_constructor(
            get_uuid_string_from_bytes_mock.return_value,
            alchemy_object.name,
            alchemy_object.descr,
            None,
            expected_sensor_ip,
            get_software_version_mock.return_value,
            None,
            self.platform_repo.get_platform.return_value is not None
        )

        actual_sensor = self.repo._AlchemySensorRepository__build_sensor_from_alchemy_object(alchemy_object)

        get_uuid_string_from_bytes_mock.assert_called_once_with(alchemy_object.id)
        get_ip_from_id_mock.assert_called_once_with(get_uuid_string_from_bytes_mock.return_value)
        self.platform_repo.get_platform.assert_called_once_with(expected_sensor_ip)
        get_software_version_mock.assert_called_once_with(alchemy_object.id)
        self.assertEqual(actual_sensor, expected_sensor)

    @patch('db.session', autospec=True)
    def test_get_sensors_empty_list(self, session_mock):
        session_mock.query.return_value = query_mock = MagicMock(spec=Query)
        query_mock.all.return_value = expected_sensors = []

        actual_sensors = self.repo.get_sensors()

        self.assertEqual(actual_sensors, expected_sensors)
    
    """

if __name__ == '__main__':
    unittest.main()
