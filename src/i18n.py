TRANSLATIONS = {
    'No working proxies found - stopping the attack': {
        'ru': 'Не найдено рабочих прокси - останавливаем атаку'
    },
    'Selected': {
        'ru': 'Выбрано'
    },
    'targets to attack': {
        'ru': 'целей для атаки'
    },
    'Target': {
        'ru': 'Цель'
    },
    'Port': {
        'ru': 'Порт'
    },
    'Method': {
        'ru': 'Метод'
    },
    'Connections': {
        'ru': "Соединения"
    },
    'Requests': {
        'ru': 'Запросы'
    },
    'Traffic': {
        'ru': 'Трафик'
    },
    'Total': {
        'ru': 'Всего'
    },
    'Loaded config': {
        'ru': 'Загружен конфиг'
    },
    'Targets loading failed': {
        'ru': 'Загрузка целей завершилась ошибкой:'
    },
    'No targets specified for the attack': {
        'ru': 'Не указаны никакие цели для атаки'
    },
    'Launching the attack ...': {
        'ru': 'Запускаем атаку...'
    },
    'Empty config loaded - the previous one will be used': {
        'ru': 'Загружен пустой конфиг - будет использован предварительный'
    },
    'Failed to (re)load targets config:': {
        'ru': 'Не удалось (пере)загрузить конфиг целей:'
    },
    'Failed to reload proxy list - the previous one will be used': {
        'ru': 'Не удалось перезагрузить список прокси - будет использован предыдущий'
    },
    'A new version is available, update is recommended': {
        'ru': 'Доступна новая версия, рекомендуем обновить'
    },
    'The number of threads has been reduced to': {
        'ru': 'Количество потоков уменьшено до'
    },
    'due to the limitations of your system': {
        'ru': 'из-за ограничения вашей системы'
    },
    'Shutting down...': {
        'ru': 'Завершаем работу...'
    },
    'The number of copies is automatically reduced to': {
        'ru': 'Количество копий автоматически уменьшено до'
    },
    'Threads': {
        'ru': 'Потоков'
    },
    'Targets': {
        'ru': 'Целей'
    },
    'Proxies': {
        'ru': 'Прокси'
    },
    'The attack also uses your IP/VPN': {
        'ru': 'Атака также использует ваш IP/VPN'
    },
    'Only your IP/VPN is used (no proxies)': {
        'ru': 'Атака использует только ваш IP/VPN (без прокси)'
    },
    'Delay in execution of operations detected': {
        'ru': 'Зафиксированная задержка при выполнении операций'
    },
    'the attack continues, but we recommend reducing the workload': {
        'ru': 'атака продолжается, но рекомендуем уменьшить значение нагрузки'
    },
    'Workload (number of threads)': {
        'ru': 'Погрузка (количество потоков)'
    },
    'use flag `-t XXXX`, default is': {
        'ru': 'параметр `-t XXXX`, по умолчанию -'
    },
    'Glory to Russia!!!': {
        'ru': 'Слава России!!!'
    },
    'Consider adding your IP/VPN to the attack - use flag `--vpn`': {
        'ru': 'Чтобы использовать ваш IP/VPN в дополнение к прокси: параметр `--vpn`'
    },
    'Instead of high `-t` value consider using': {
        'ru': 'Вместо высокого значения `-t` лучше использовать'
    },
    '`uvloop` activated successfully': {
        'ru': '`uvloop` успешно активировано'
    },
    '(increased network efficiency)': {
        'ru': '(повышенная эффективность работы с сетью)'
    },
    'for': {
        'ru': 'на'
    },
    'targets': {
        'ru': 'целей'
    },
    'targets for the attack': {
        'ru': 'целей для атаки'
    },
    "is not available and won't be attacked": {
        'ru': 'не доступна и не будет атакована'
    }
}

LANGUAGES = ['ru', 'en']
DEFAULT_LANGUAGE = LANGUAGES[0]


class _Translations:
    def __init__(self):
        self.language = None
        self.translations = TRANSLATIONS

    def set_language(self, language: str):
        assert language in LANGUAGES
        self.language = language

    def translate(self, key: str) -> str:
        try:
            return self.translations[key][self.language]
        except KeyError:
            return key


_inst = _Translations()

set_language = _inst.set_language
translate = _inst.translate
