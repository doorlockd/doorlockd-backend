from asyncio import format_helpers
from concurrent.futures import thread
from mimetypes import init

# from multiprocessing.sharedctypes import synchronized
# from select import KQ_EV_SYSFLAGS
from sre_compile import isstring
from django.db import models
from django.db.models import F, Q
from django.db.models import Max, OuterRef, Subquery
from django.core.exceptions import ValidationError
from django.utils.functional import cached_property

# for AuthWithByClientSSL: unquote HTTP header.
from urllib.parse import unquote

import json

import datetime
from django.utils import timezone

import hashlib

import logging

logger = logging.getLogger(__name__)


#
# legacy code
#

# random_token used in :...
# /Users/diederik/Werkmap/doorlockdbackend/doorlockdb/migrations/0001_initial.py
# /Users/diederik/Werkmap/doorlockdbackend/doorlockdb/migrations/0009_alter_lock_token.py
# /Users/diederik/Werkmap/doorlockdbackend/doorlockdb/migrations/0010_lock_certificate_alter_lock_token.py
from django.utils.crypto import get_random_string


def random_token():
    return get_random_string(length=64)


# /end of legacy code


def getServerSSLFingerprint():
    # get SSL certificate file:
    from django.conf import settings

    try:
        certfile = settings.SERVER_SSL_CERTIFICATE
    except AttributeError:
        return "Error: SERVER_SSL_CERTIFICATE is not defined in settings.py"

    # open certfile
    try:
        with open(certfile) as f:
            cert = f.read()
    except FileNotFoundError as e:
        return f"Error: {e}. \n(see SERVER_SSL_CERTIFICATE in settings.py)."
    # what if file doesn;t exist?

    # # ...
    # return cert
    # return("Fi:ng:er:pr:in:t.")

    import base64
    import hashlib

    # find begin
    begin_cert = cert.find("-----BEGIN CERTIFICATE-----") + 27
    end_cert = cert.find("-----END CERTIFICATE-----")

    if begin_cert == -1 or end_cert == -1:
        raise Exception(
            "No Certificate found! ('-----BEGIN CERTIFICATE-----' and '-----END CERTIFICATE-----' are missing )"
        )

    return hashlib.sha256(base64.b64decode(cert[begin_cert:end_cert])).hexdigest()


class Person(models.Model):
    name = models.CharField(max_length=32, unique=True)
    email = models.EmailField(unique=True, blank=True, null=True, default=None)
    info = models.CharField(max_length=200, blank=True)
    is_enabled = models.BooleanField(default=True)
    personsgroup = models.ManyToManyField(
        "PersonGroup", blank=True, related_name="persons"
    )

    # created_at = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name}"
        return f"{self.__class__.__name__}(name={self.name}, email={self.email})"

    def set_check_any_out_of_sync(self, lock_list):
        self._cached_lock_list = lock_list

    def check_any_out_of_sync(self):
        # is self._cached_lock_list set ?
        return checkAnyOutOfSync(self, self._cached_lock_list)

    @cached_property
    def last_seen_start(self):
        return self.key_set.aggregate(
            last_seen_start=Max("logkeylastseen__last_seen_start")
        )["last_seen_start"]

    @cached_property
    def last_seen_end(self):
        return self.key_set.aggregate(
            last_seen_end=Max("logkeylastseen__last_seen_end")
        )["last_seen_end"]


class PersonGroup(models.Model):
    name = models.CharField(max_length=32, unique=True)
    # persons = models.ManyToManyField('Person', blank=True)
    # description = models.CharField(max_length=200, blank=True)
    access_groups = models.ManyToManyField("AccessGroup", blank=True)
    is_enabled = models.BooleanField(default=True)

    def __str__(self):
        return self.name
        # return f'{self.__class__.__name__}(name={self.name})'


class AccessGroup(models.Model):
    name = models.CharField(max_length=32, unique=True)
    # description = models.CharField(max_length=200, blank=True)
    # person_groups = models.ManyToManyField('PersonGroup', blank=True)

    locks = models.ManyToManyField("Lock", blank=True)
    # is_enabled = models.BooleanField(default=True)
    rules = models.ForeignKey("AccessRuleset", on_delete=models.CASCADE)

    def __str__(self):
        return self.name
        # locklist = []
        # for l in self.locks.all():
        #     locklist.append(l.name)

        # return f'{self.__class__.__name__}(name={self.name}, rules={self.rules.name}, locks={locklist})'
        # # return f'{self.__class__.__name__}(name={self.name})'


class AccessRuleset(models.Model):
    name = models.CharField(max_length=64, unique=True)

    def __str__(self):
        return self.name
        return f"{self.__class__.__name__}(name={self.name})"


class AccessRule(models.Model):
    # parent = models.ForeignKey('AccessRuleset', blank=True, null=True, related_name='rules', on_delete=models.CASCADE)
    parent = models.ForeignKey("AccessRuleset", on_delete=models.CASCADE)

    # datetime
    after = models.DateTimeField(blank=True, null=True, default=None)
    before = models.DateTimeField(blank=True, null=True, default=None)

    # weekdays [0,1,2,3,4,5,6]
    weekdays_monday = models.BooleanField(default=False)
    weekdays_tuesday = models.BooleanField(default=False)
    weekdays_wednesday = models.BooleanField(default=False)
    weekdays_thursday = models.BooleanField(default=False)
    weekdays_friday = models.BooleanField(default=False)
    weekdays_saturday = models.BooleanField(default=False)
    weekdays_sunday = models.BooleanField(default=False)

    # self.timeslot = timeslot
    time_start = models.TimeField(blank=True, null=True, default=None)
    time_end = models.TimeField(blank=True, null=True, default=None)

    def __str__(self):
        # return f'{self.__class__.__name__}({self.parent.name})'
        return str(Helpers.exportAccessRule(self))
        return f"{self.__class__.__name__}({self.parent.name}# {str( Helpers.exportAccessRule(self))})"


#
# KeyMetaData
#
class AddKeyMetaDataModelMixin:
    """Adds meta_info cached property from KeyMetaData(Model) (for *Key related models)"""

    @cached_property
    def meta_data_dict(self):
        return json.loads(self.meta_data_json)

    @cached_property
    def meta_info(self):
        """Makes it easier to find the UnknownKey we are looking for, perhaps it makes it very slow too"""
        meta_list = []

        # print(f"DEBUG KeyMetaInfo: self: {self}, id:{self.id}, hwid:{self.hwid}")

        #
        # OV chipkaart validuntil:
        #
        try:
            meta_list.append(
                "OV Chipkaart valid "
                + self.meta_data_dict.get("ovchipkaart", {})["validuntil"]
            )
        except:
            pass

        #
        # NFC Tag product version:
        #
        try:
            meta_list.append("Tag " + self.meta_data_dict.get("tag", {})["product"])
        except:
            pass

        return meta_list


class AddKeyMetaDataQuerySetMixin:
    def with_meta_data_json(self):
        """
        Adds meta_data_json annotation.

        This is the raw json value of meta_data.
        """
        return self.annotate(
            meta_data_json=Subquery(
                KeyMetaData.objects.filter(hwid=OuterRef("hwid")).values(
                    "meta_data_json"
                )
            )
        )


class KeyMetaData(AddKeyMetaDataModelMixin, models.Model):
    """MetaData on NFC Keys."""

    hwid = models.CharField(max_length=32, unique=True)
    meta_data_json = models.TextField(default="{}")  # default json('{}')

    def __str__(self):
        return f"{self.hwid} {self.meta_info}"

    def merge_meta_data_json(self, meta_data={}):
        """Merge new meta_data_json with existing self.meta_data_json."""
        meta_data = {**self.meta_data_dict, **meta_data}
        self.meta_data_json = json.dumps(meta_data, indent=4)


#
# Key:
#
class KeyQuerySet(AddKeyMetaDataQuerySetMixin, models.QuerySet):
    """return custom Key annotations"""


class KeyManager(models.Manager.from_queryset(KeyQuerySet)):
    pass


class Key(AddKeyMetaDataModelMixin, models.Model):
    """
    Stores a single Key/rfidtag, related to :model:`doorlockdb:Person` and
    :model:`auth.User`.
    """

    hwid = models.CharField(max_length=32, unique=True)
    owner = models.ForeignKey(
        "Person",
        on_delete=models.CASCADE,
    )
    description = models.CharField(
        max_length=200,
        help_text='Enter a meaningful description. example="NS OV chipkaart t.h.t. 02-2027"',
    )
    is_enabled = models.BooleanField(default=True)

    # created_at = models.DateTimeField(auto_now_add=True)
    # updated_at = models.DateTimeField(auto_now=True)

    objects = KeyManager()

    @cached_property
    def last_seen_start(self):
        try:
            return self.logkeylastseen.last_seen_start
        except Key.logkeylastseen.RelatedObjectDoesNotExist:
            return None

    @cached_property
    def last_seen_end(self):
        try:
            return self.logkeylastseen.last_seen_end
        except Key.logkeylastseen.RelatedObjectDoesNotExist:
            return None

    def __str__(self):
        return f"Key #{self.id}"

    def clean(self):
        # lowercase all keys:
        self.hwid = self.hwid.lower()

        # random hwid (^08:)
        if self.hwid[0:2] == "08":
            raise ValidationError(
                {
                    "hwid": "This is an non-unique random hardware identifier, they are not allowed."
                }
            )

    # make sure the clean() method is called on each save()
    def save(self, *args, **kwargs):
        self.full_clean()
        try:
            result = super().save(*args, **kwargs)

            # delete LogUnknownKey with this hwid
            logme = LogUnknownKey.objects.filter(hwid=self.hwid).delete()
            logger.info(f"related LogUnknownKey removed: {str(logme)}")

        except Exception as e:
            raise e


class LogKeyLastSeen(models.Model):
    #
    # LastSeen:
    #
    # last_seen = start ... end # precision period. (larger period used for more privacy)
    key = models.OneToOneField("Key", on_delete=models.CASCADE, primary_key=True)
    lock = models.ForeignKey("Lock", on_delete=models.SET_NULL, null=True)
    counter = models.SmallIntegerField(default=0)

    last_seen_start = models.DateTimeField(blank=True, null=True, default=None)
    last_seen_end = models.DateTimeField(blank=True, null=True, default=None)

    def __str__(self):
        return f"{self.__class__.__name__}(key.hwid={self.key.hwid})"

    def addLastSeen(hwid, lock, last_seen_start, last_seen_end, count=1):
        #
        # set lock last_seen stats:
        #
        SyncLockKeys.objects.filter(lock=lock).update(last_log_keys=timezone.now())

        if isstring(last_seen_start):
            last_seen_start = datetime.datetime.fromisoformat(last_seen_start)

        if isstring(last_seen_end):
            last_seen_end = datetime.datetime.fromisoformat(last_seen_end)

        #   lookup
        try:
            k = Key.objects.get(hwid=hwid)
        except Key.DoesNotExist:
            logger.critical(
                f"LastSeen update failed: Key ({hwid}) doesn't exist! ({hwid}, {lock}, {last_seen_start}, {last_seen_end}, {count})"
            )
            return

        # update  last_seen_end if newer, last_seen_start if newer, update count, update lock
        k_log, bool_value_is_new = LogKeyLastSeen.objects.get_or_create(
            key=k,
            defaults={
                "last_seen_start": last_seen_start,
                "last_seen_end": last_seen_end,
                "counter": count,
                "lock": lock,
            },
        )
        if not bool_value_is_new:
            # last_seen_start
            if k_log.last_seen_start is None or last_seen_start > k_log.last_seen_start:
                k_log.last_seen_start = last_seen_start

            # last_seen_end
            if k_log.last_seen_end is None or last_seen_end > k_log.last_seen_end:
                k_log.last_seen_end = last_seen_end

            # counter
            k_log.counter += count

            # lock
            k_log.lock = lock

        k_log.save()


class Lock(models.Model):
    name = models.CharField(max_length=32, unique=True)
    description = models.CharField(max_length=200, blank=True)
    is_enabled = models.BooleanField(
        default=True,
        help_text="Disable access for all keys on this lock. This lock is still able to synchronize with it's SSL certificate.",
    )
    # last_synced = models.DateTimeField(null=True,default=None)
    certificate = models.TextField(
        max_length=2000,
        unique=True,
        null=True,
        default=None,
        blank=True,
        help_text=f"Paste client certitificate here (including '-----BEGIN CERTIFICATE-----' and '-----END CERTIFICATE-----').<br>\n<br>\nOn the client configure this server server Fingerprint. (hint: restart django after server ssl certificate is changed). <br>\n<code>server_ssl_fingerprint='{getServerSSLFingerprint()}'</code>",
    )

    def __str__(self):
        return f"{self.name}"
        return f"{self.__class__.__name__}(name={self.name})"

    @cached_property
    def custom_all_persons(self):
        """return all Person object who have access to this lock"""
        print(f"DEBUG: Query custom_all_persons. Lock({self.id})")
        # return Person.objects.filter(group__is_enabled=True, group__access=self, is_enabled=True).distinct()
        return Person.objects.filter(
            is_enabled=True,
            personsgroup__is_enabled=True,
            personsgroup__access_groups__locks=self,
        ).distinct()

    def custom_all_keys(self):
        """return all Keys object who have access to this lock"""

        if not self.is_enabled:
            return []

        return Key.objects.filter(
            is_enabled=True,
            owner__is_enabled=True,
            owner__personsgroup__is_enabled=True,
            owner__personsgroup__access_groups__locks=self,
        ).distinct()

    def custom_all_keys_list(self):
        """ "same as customer_all_keys(), but then simply return a list of hardware IDs. ['a0:xx', '0a:xx']"""
        result = []

        for k in self.custom_all_keys():
            result.append(k.hwid)

        return result

    def is_out_of_sync(self):
        """custom: return if objec is affected by syncronisation issues."""
        try:
            return not self.synclockkeys.synchronized
        except Lock.synclockkeys.RelatedObjectDoesNotExist:
            self.check_sync()
            return not self.synclockkeys.synchronized

    def check_sync(self):
        """update synchronization field"""
        # update synchronized field
        sync, created = SyncLockKeys.objects.get_or_create(lock=self)

        #
        if sync.synchronized is not sync.check_sync():
            print(f"check_sync: update Lock synchronized ({self.name})")
            sync.synchronized = False
            sync.save()

    @staticmethod
    def cleanup_certificate(certificate):
        # fix empty -> None, only validate when set.
        if certificate == "" or certificate is None:
            return None

        # replace \r\n with \n , and remove all other tabs and spaces (like how nginx shows it)
        certificate = (
            certificate.replace("\r\n", "\n").replace("\t ", "").strip() + "\n"
        )

        if (
            certificate == ""
            or certificate.splitlines()[0] != "-----BEGIN CERTIFICATE-----"
            or certificate.splitlines()[-1] != "-----END CERTIFICATE-----"
        ):
            raise ValidationError(
                {
                    "certificate": "Must begin with '-----BEGIN CERTIFICATE-----' and end with '-----END CERTIFICATE-----'"
                }
            )

        return certificate

    def clean(self):
        self.certificate = Lock.cleanup_certificate(self.certificate)

    # make sure the clean() method is called on each save()
    def save(self, *args, **kwargs):
        self.full_clean()
        try:
            result = super().save(*args, **kwargs)
        except Exception as e:
            raise e


#
# LogUnknownKey
#


class LogUnknownKeyQuerySet(AddKeyMetaDataQuerySetMixin, models.QuerySet):
    """return custom LogUnknownKey annotations"""


class LogUnknownKeyManager(models.Manager.from_queryset(LogUnknownKeyQuerySet)):
    pass


class LogUnknownKey(AddKeyMetaDataModelMixin, models.Model):
    hwid = models.CharField(max_length=32, unique=True)
    lock = models.ForeignKey("Lock", on_delete=models.SET_NULL, null=True)
    counter = models.SmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_seen = models.DateTimeField(blank=True, null=True, default=None)

    objects = LogUnknownKeyManager()

    class Meta:
        unique_together = ("hwid", "lock")

    def register(hwid, lock, last_seen=None, count=1, meta_data_json="{}"):
        #
        # set lock last_seen stats:
        #
        SyncLockKeys.objects.filter(lock=lock).update(
            last_log_unknownkeys=timezone.now()
        )

        # translate hwid to lowercase:
        hwid = hwid.lower()
        u, created = LogUnknownKey.objects.get_or_create(hwid=hwid)

        #
        # create or merge KeyMetaData:
        #
        md, created = KeyMetaData.objects.get_or_create(hwid=hwid)
        md.merge_meta_data_json(meta_data_json)
        md.save()

        # do + count
        LogUnknownKey.objects.filter(hwid=hwid).update(
            lock=lock,
            last_seen=last_seen,
            counter=F("counter") + count,
        )
        # return counter value
        return u.counter + count

    def __str__(self):
        return f"{self.__class__.__name__} #{self.id}"


# los method for checkAnyOutOfSync
def checkAnyOutOfSync(other_obj, lock_list=None):
    result = []

    if lock_list is None:
        lock_list = Lock.objects.all()

    # check all locks sync related objects
    for l in lock_list:
        l_result = l.synclockkeys.is_object_related_out_of_sync(other_obj)
        if l_result:
            # return [..., ('match str', Lock object),..]
            result.append((l_result, l))

    # only return list when there is something in it
    if result:
        return result


class Helpers:
    class ErrorClientSSLCert(Exception):
        pass

    @classmethod
    def AuthWithByClientSSL(cls, request=None, scope=None):
        # get http_x_ssl_cert from headers
        try:
            # normal django request
            if request:
                http_x_ssl_cert = request.META["HTTP_X_SSL_CERT"]

            # websocket scope
            if scope:
                http_x_ssl_cert = [
                    v for (k, v) in scope["headers"] if k == b"x-ssl-cert"
                ][0].decode()

        except:
            raise cls.ErrorClientSSLCert(
                "no client certificate found (HTTP_X_SSL_CERT missing)"
            )

        # lookup in db:
        try:
            client_cert = Lock.cleanup_certificate(unquote(http_x_ssl_cert))
        except ValidationError as e:
            raise cls.ErrorClientSSLCert(
                "malformed client certificate (HTTP_X_SSL_CERT)."
            )
        except:
            raise cls.ErrorClientSSLCert(
                "no client certificate found (HTTP_X_SSL_CERT missing)"
            )

        try:
            lock = Lock.objects.get(certificate=client_cert)
            # update last_seen timestamp
            SyncLockKeys.objects.filter(lock=lock).update(last_seen=timezone.now())
            return lock

        except Lock.DoesNotExist as e:
            raise cls.ErrorClientSSLCert(
                f"Client SSL Certificate is unkown ({e})\nCertificate: '{client_cert}'."
            )

    @classmethod
    def exportAccessRuleset(cls, accessruleset: AccessRuleset):
        #
        # merge accessrules into a single accesruleset
        #
        result = []
        for ar in accessruleset.accessrule_set.all():
            result.append(cls.exportAccessRule(ar))

        return result

    @classmethod
    def exportAccessRule(cls, accessrule: AccessRule):
        #
        # put Weekdays into a single list:
        #   weekdays = list [int,...]
        weekdays = []  # empty weekdays == no access
        # ...
        if accessrule.weekdays_monday:
            weekdays.append(0)
        if accessrule.weekdays_tuesday:
            weekdays.append(1)
        if accessrule.weekdays_wednesday:
            weekdays.append(2)
        if accessrule.weekdays_thursday:
            weekdays.append(3)
        if accessrule.weekdays_friday:
            weekdays.append(4)
        if accessrule.weekdays_saturday:
            weekdays.append(5)
        if accessrule.weekdays_sunday:
            weekdays.append(6)

        # collect rules
        result = {}
        # result = {'after':None, 'before':None, 'weekdays':None, 'time_start':None, 'time_end':None}

        if accessrule.after is not None:
            result["after"] = str(accessrule.after)
        if accessrule.before is not None:
            result["before"] = str(accessrule.before)
        if weekdays is not None:
            result["weekdays"] = weekdays
        if accessrule.time_start is not None:
            result["time_start"] = str(accessrule.time_start)
        if accessrule.time_end is not None:
            result["time_end"] = str(accessrule.time_end)

        return result

    @classmethod
    def create_accesslist_for_lock__dict(cls, lock: Lock):
        # accesslist in the format how the locks will get it over the api.
        # example:
        # {'hwid': {'ruleset': [ {$rule}, {$rule}, ...]}}
        #
        # rules have format: {''}
        result = {}

        # is lock enabled
        if lock.is_enabled is not True:
            # return empty list:
            return result

        # for each AccessGroup related to lock
        for ag in AccessGroup.objects.filter(locks=lock):
            # get ruleset for this AccessRuleset (dict)
            ruleset = Helpers.exportAccessRuleset(ag.rules)

            #
            # get Keys for this AccessRuleset
            #
            keys = []
            for pg in PersonGroup.objects.filter(
                access_groups=ag, is_enabled=True
            ).all():
                for p in pg.persons.filter(is_enabled=True):
                    for k in p.key_set.with_meta_data_json().filter(is_enabled=True):
                        keys.append(k)

            #
            # now add keys and ruleset to the result
            #
            for k in keys:
                # merge ruleset
                if k.hwid not in result.keys():
                    # add hwid + empty ruleset
                    result[k.hwid] = {"ruleset": []}

                    # has no meta data?
                    if not k.meta_data_json:
                        result[k.hwid]["need_meta_data"] = True

                # append this ruleset to the rulessets
                # result[k.hwid]['ruleset'] += ruleset
                for rule in ruleset:
                    if rule not in result[k.hwid]["ruleset"]:
                        result[k.hwid]["ruleset"].append(rule)
                        # print(f"DEBUG: appending data for key {k.hwid}: acceslist {ag.name}. ", rule)

        return result

    @classmethod
    def related_objects_for_lock(cls, lock: Lock):
        r = {}

        r["AccessGroup"] = AccessGroup.objects.filter(locks=lock)
        r["PersonGroup"] = PersonGroup.objects.filter(
            access_groups__in=r["AccessGroup"]
        )
        r["Person"] = Person.objects.filter(personsgroup__in=r["PersonGroup"])
        r["Key"] = Key.objects.filter(owner__in=r["Person"])

        # # get orphaned keys
        # r['orphaned_keys'] = []
        # synclockkeys, created = SyncLockKeys.objects.get_or_create(lock=lock)
        # for hwid in json.loads( synclockkeys.keys_json).keys():
        #     if not r['Key'].filter(hwid=hwid):
        #         r['orphaned_keys'].append(hwid)

        return r

    @classmethod
    def create_accesslist_for_lock__json(cls, lock: Lock):
        return json.dumps(cls.create_accesslist_for_lock__dict(lock))

    @classmethod
    def get_hash_for_dict(cls, data):
        if isstring(data):
            try:
                data = json.loads(data)
            except:
                return "no valid data"

        return hashlib.new(
            "SHA256", json.dumps(data, sort_keys=True).encode("utf-8")
        ).hexdigest()

    @classmethod
    def create_keys_patch(cls, lock: Lock):
        #
        # >>>   Playing arround  <<<<
        # also usefull for Persons/Keys affected when lock is out of sync
        # need more testing!!!!!
        p = []  # empty patch

        # get both dicts , k1 live, k2 from db
        k1 = json.loads(lock.synclockkeys.keys_json)
        k2 = cls.create_accesslist_for_lock__dict(lock)
        k1_keys = list(k1.keys())
        k2_keys = list(k2.keys())
        for k in set(k1_keys + k2_keys):
            # add key
            if k not in k1_keys:
                p.append({"op": "add", "path": f"/{k}", "value": k2[k]})

            # remove key
            elif k not in k2_keys:
                p.append({"op": "remove", "path": f"/{k}"})

            # replace key
            elif k1[k] != k2[k]:
                p.append({"op": "replace", "path": f"/{k}", "value": k2[k]})
            # # no change
            # else
            #     pass
        return p


class SyncLockKeys(models.Model):
    lock = models.OneToOneField("Lock", on_delete=models.CASCADE, primary_key=True)
    config_time = models.DateTimeField(blank=True, null=True, default=None)
    last_seen = models.DateTimeField(
        blank=True, null=True, default=None
    )  # last authenitcated

    last_sync_keys = models.DateTimeField(blank=True, null=True, default=None)
    last_log_unknownkeys = models.DateTimeField(blank=True, null=True, default=None)
    last_log_keys = models.DateTimeField(blank=True, null=True, default=None)

    keys_json = models.TextField(default="{}")  # default json('{}')
    synchronized = models.BooleanField(default=False, null=True)

    def compare_hash_and_sync(self, lock_keys_hash):

        # get accesslist for this lock
        db_keys_config = Helpers.create_accesslist_for_lock__dict(self.lock)

        # compare hash
        if Helpers.get_hash_for_dict(db_keys_config) == lock_keys_hash:
            # we are good.
            self.config_time = timezone.now()
            self.keys_json = json.dumps(db_keys_config)
            self.synchronized = True
            # set last_sync_keys timestamp
            self.last_sync_keys = timezone.now()
            self.save()

            # return: no-update, no new data:
            return False, None
        elif Helpers.get_hash_for_dict(self.keys_json) == lock_keys_hash:
            #  self.keys_json is still what the lock has.
            # return: need-update, new data (future idea: send patch?)
            self.synchronized = False
            self.save()

            return True, db_keys_config
        else:
            #  self.keys_json is not what is on the lock !.
            self.keys_json = '{"out of sync": true}'
            self.synchronized = False
            self.save()

            # return: need-update, new data:
            return True, db_keys_config

    def check_sync(self):
        # check if db compares to keys_json:
        db_keys = Helpers.create_accesslist_for_lock__dict(self.lock)
        db_keys_hash = Helpers.get_hash_for_dict(db_keys)
        sync_keys_hash = Helpers.get_hash_for_dict(self.keys_json)

        return db_keys_hash == sync_keys_hash

    # need fix?
    @cached_property
    def custom_related_out_of_sync(self):
        """related out of sync object"""
        logger.debug("DEBUG  cache custom_related_out_of_sync ")
        data = {
            "warning_some_keys_left": False,
            "persons": set(),
            "keys_add": [],
            "keys_del": [],
            "orphaned_keys": [],
        }

        if self.synchronized:
            return data

        # get keys_live compare with
        #
        keys_live = json.loads(self.keys_json).keys()  # get just the hwid from keys
        keys_db = self.lock.custom_all_keys()

        # create hwid list from keys_db
        keys_db_list = []
        for k in keys_db:
            keys_db_list.append(k.hwid)

        # keys to add on live
        for k in keys_db:
            if k.hwid not in keys_live:
                data["keys_add"].append(k)

                # add person:
                data["persons"].add(k.owner)

        # keys to del on live
        for hwid in keys_live:
            if hwid not in keys_db_list:
                try:
                    k = Key.objects.get(hwid=hwid)
                    data["keys_del"].append(k)

                    # add person:
                    data["persons"].add(k.owner)

                except Key.DoesNotExist:
                    data["orphaned_keys"].append(hwid)

        # set this boolean True if there are any keys left with access on the lock wich shouldn't
        data["warning_some_keys_left"] = bool(data["keys_del"] + data["orphaned_keys"])

        return data

    # need fix?
    def is_object_related_out_of_sync(self, other_obj):
        if self.synchronized:
            return False

        # Key obj
        if isinstance(other_obj, Key):
            if other_obj in self.custom_related_out_of_sync["keys_add"]:
                return "keys_add"
            if other_obj in self.custom_related_out_of_sync["keys_del"]:
                return "keys_del"

        # Person obj
        elif isinstance(other_obj, Person):
            if other_obj in self.custom_related_out_of_sync["persons"]:
                return "persons"

        # Str
        elif isinstance(other_obj, str):
            if other_obj in self.custom_related_out_of_sync["orphaned_keys"]:
                return "orphaned_keys"

        # no match
        return False

    def __str__(self):
        return f"{self.__class__.__name__}(lock={self.lock.name}, synchronized={self.synchronized}) "


#
# WebSocket related Models:
#
class LockWebsocketChannel(models.Model):
    lock = models.OneToOneField("Lock", on_delete=models.CASCADE, primary_key=True)
    channel_name = models.CharField(max_length=100, unique=True)
    persistent_name = models.CharField(max_length=64, unique=True)

    def save(self, *args, **kwargs):
        if not self.persistent_name:
            obj = self.lock
            self.persistent_name = f"{obj.__class__.__name__}.{obj.pk}"

        try:
            result = super().save(*args, **kwargs)
        except Exception as e:
            raise e

    async def send_button_lock(self, channel_layer, button_bool):
        """for testing purpose only"""
        await self.send_to_lock(
            channel_layer, {"button": button_bool}, add_type="chat.message"
        )

    async def send_to_lock(self, channel_layer, data={}, add_type=None):
        """for testing purpose only"""
        if add_type:
            data["type"] = add_type

        # send dict to LockConsumer.{data['type']| tr . _ }
        await channel_layer.send(self.channel_name, data)


#
# cleanup old LockWebsocketChannel on startup:
#
from django.core.checks import Info, register


@register()
def cleanup_LockWebsocketChannel(app_configs, **kwargs):
    errors = []

    # if database=None : no database allowed, cleanup ingored
    if not kwargs.get("database", True):
        return errors

    # cleanup old LockWebsocketChannel on startup:
    result, objects = LockWebsocketChannel.objects.all().delete()

    if result:
        errors.append(
            Info(
                f"{result} orphaned LockWebsocketChannel are deleted",
                # hint="Solved. No actions required.",
                obj=LockWebsocketChannel,
                id="LockWebsocketChannel.cleanup.I001",
            )
        )
    return errors


#
# Signals:
#
from django.db.models.signals import post_save, post_delete, m2m_changed


def post_update_check_sync(sender, **kwargs):
    # LOGGER:  {
    # 'signal': <django.db.models.signals.ModelSignal object at 0x109707a30>,
    # 'sender': <class 'doorlockdb.models.SyncLockKeys'>,
    # 'instance': <SyncLockKeys: SyncLockKeys(lock=matter, synchronized=True) >,
    # 'created': False,
    # 'update_fields': None,
    # 'raw': False,
    # 'using': 'default'}

    # print(f"SIGNAL debug: {sender}", kwargs)

    if sender is Lock:
        # print(f"SIGNAL 1 lock: {sender}", kwargs)
        lock = kwargs.get("instance")
        # to save SQLqueries we no longer do lock.check_sync(),
        # we now only mark this one as sync status unknown (None)
        synclockkey, is_created = SyncLockKeys.objects.get_or_create(lock=lock)
        synclockkey.synchronized = None
        synclockkey.save()

    # if(sender in [ Key, Group, Person ]):
    elif type(kwargs.get("instance")) in [
        Key,
        PersonGroup,
        AccessGroup,
        AccessRule,
        AccessRuleset,
        Person,
    ]:
        if kwargs.get("action", "not set") in ["pre_add", "pre_remove"]:
            return

        # print(f"SIGNAL match: {sender}", kwargs)
        # to save SQLqueries we no longer do lock.check_sync() for lock in Lock.objects.all(),
        # we now only mark all locks as sync status unknown:
        SyncLockKeys.objects.update(synchronized=None)


def post_delete_check_sync(sender, **kwargs):
    # print(f"SIGNAL post_delete: {sender}", kwargs)

    if sender is Lock:
        # print(f"SIGNAL 1 lock: IGNORE this :)# {sender}", kwargs)
        return
        # lock = kwargs.get('instance')
        # lock.check_sync()

    # if(sender in [ Key, Group, Person ]):
    elif type(kwargs.get("instance")) in [
        Key,
        PersonGroup,
        AccessGroup,
        AccessRule,
        AccessRuleset,
        Person,
    ]:
        if kwargs.get("action", "not set") in ["pre_add", "pre_remove"]:
            return

        # print(f"SIGNAL match: {sender}", kwargs)
        # to save SQLqueries we no longer do lock.check_sync() for lock in Lock.objects.all(),
        # we now only mark all locks as sync status unknown:
        SyncLockKeys.objects.update(synchronized=None)


post_save.connect(post_update_check_sync)
post_delete.connect(post_delete_check_sync)
m2m_changed.connect(post_update_check_sync)


##
## Threading idea:
##
# from django.db.models.signals import post_save, post_delete
# import threading
# import time

# class PostUpdaterD:
#     def __init__(self):
#         print("LOGGER, init PostUpdaterD ")
#         self.lock_trigger = threading.Lock()
#         self.lock_trigger.acquire()
#         self.thread = threading.Thread(target=self.run, daemon=True)
#         self.thread.start()


#     def trigger(self):
#         #
#         # we trigger the run loop, by releasing the lock.
#         #
#         if self.lock_trigger.locked():
#             self.lock_trigger.release()

#             print("LOGGER, THREAD trigger")

#     def run(self):
#         print("LOGGER, THREAD run loop start")

#         # loop forever..
#         while( True ):
#             # we start the loop when lock is acquired ()
#             self.lock_trigger.acquire()

#             # do some waiting magic: we wait 3 seconds
#             time.sleep(3)
#             self.lock_trigger.acquire(blocking=False)

#             # now do out magic.
#             print("LOGGER, THREAD run loop LKAJSLKJASDLKAJSD")


# post_update_ding = PostUpdaterD()
# post_update_ding.trigger()

# def receiver_function(**kwargs):
#     global post_update_ding
#     print("LOGGER: ", kwargs)
#     post_update_ding.trigger()

# post_save.connect(receiver_function )
# post_delete.connect(receiver_function )
