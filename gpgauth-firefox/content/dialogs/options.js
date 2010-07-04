/*
    Function: onLoad
    This function is called when the options.xul form is shown.
*/
function onLoad(win) {
    keylist = JSON.parse(document.getElementById("gpgAuthPlugin").getKeyList())

    if (keylist)
        gpg_keys = keylist;
    else
        gpg_keys = new Array();

    getIgnored_servers( document.getElementById('domain_list') );

    var listbox = document.getElementById('public-keyslist-children');

    /* populate the public-key list */
    var current = 0;
    for(var key in gpg_keys) {
        if (gpg_keys[key].name) {
            current++;
            item = CreateTreeItemKey(gpg_keys[key], document);
            if (gpg_keys[key].uids.length > 0) {
                item.setAttribute("container", "true");
                var subChildren=document.createElement("treechildren");
                for(var uid in gpg_keys[key].uids) {
                    if (gpg_keys[key].uids[uid].uid) {
                        var subItem = CreateTreeItemKey( gpg_keys[key].uids[uid], document);
                        subChildren.appendChild(subItem);
                    }
                    item.appendChild(subChildren);
                }
            }
            listbox.appendChild(item);
        }
    }
}

/*
  Function: CreateTreeItemKey
  Return a Treeitem for the key in parameter
  Parameters:
    key - The key
    document - The current document.
*/
function CreateTreeItemKey (key, document) {
    var  item  = document.createElement('treeitem');

    var row = document.createElement('treerow');

    var  col1 = document.createElement('treecell');
    if (key.name) {
        col1.setAttribute('label', key.name);
    } else {
        col1.setAttribute('label', key.uid);
    }
    row.appendChild(col1);

    var  col2 = document.createElement('treecell');
    if (key.name) {
        col2.setAttribute('label', key.fingerprint.substr(-8));
    } else {
        col2.setAttribute('label', key.validity);
    }
    row.appendChild(col2);

    var  col3 = document.createElement('treecell');
    col3.setAttribute('label', key.fingerprint);
    row.appendChild(col3);

    var  col4 = document.createElement('treecell');
    col4.setAttribute('label', key.valid);
    row.appendChild(col4);

    var id = key.keyId;

    if (forceId != undefined)
        id = forceId;

    row.setAttribute('gpg-id', id);

    item.appendChild(row);

    return item;


}

/*
    Function: getIgnored_servers
    generates a list of servers in which the user
    has set to ignore gpgAuth events
*/
function getIgnored_servers (parent) {
    var prefs = Components.classes["@mozilla.org/preferences-service;1"].
            getService(Components.interfaces.nsIPrefService);
    prefs = prefs.getBranch("extensions.gpgauth.domain_options.");
    var pref_list = prefs.getChildList("", {});
    pref_list.sort()
    // Create an object to assign friendly names to their ugly counterpart.
    var friendly_names = new Object();
    friendly_names[ 'allow_keyring' ] = "Allow access to GPG keyring";
    friendly_names[ 'ignore_not_trusted' ] = "Ignore if key not trusted in GPG Keyring";
    friendly_names[ 'ignore_server_keyerror' ] = "Ignore if key not found in GPG Keyring";
    var preferences = document.getElementById( "preferences_gpgauth" );
    for ( var pref in pref_list ) {
        var listitem = document.createElement( "listitem" );
        listitem.setAttribute( 'disabled', false );
        listitem.setAttribute( 'allowevents', true );
        listitem.setAttribute( 'type', "checkbox" );
        var listcell = document.createElement( "listcell" );
        listcell.setAttribute( 'label', pref_list[ pref ].substring( 0, pref_list[ pref ].lastIndexOf( "." ) ) );
        listitem.appendChild( listcell );
        listcell = document.createElement( "listcell" );
        var pref_name = pref_list[ pref ].substring( pref_list[ pref ].lastIndexOf( "." ) + 1, pref_list[ pref ].length );
        listcell.setAttribute( 'label', friendly_names[ pref_name ] );
        listitem.appendChild( listcell );
        listcell = document.createElement( "listcell" );
        listcell.setAttribute( 'type', "checkbox" );
        listcell.setAttribute( 'value', pref_list[ pref ] );
        listcell.setAttribute( 'name', pref_list[ pref ] );
        listcell.setAttribute( 'disabled', false );
        listcell.setAttribute( 'checked', prefs.getBoolPref( pref_list[ pref ] ) );
        listcell.setAttribute( "onclick", 'ToggleGpgAuthPref( event.target );' );
        listitem.appendChild( listcell );
        parent.appendChild( listitem );
    }
}

/*
    Function: ToggleGpgAuthPref
    This function enables/disables gpgAuth
*/
function ToggleGpgAuthPref (item) {
    var prefs = Components.classes["@mozilla.org/preferences-service;1"].
            getService(Components.interfaces.nsIPrefService);
    prefs = prefs.getBranch("extensions.gpgauth.domain_options.");
    var pref_list = prefs.getChildList("", {});
    var setting = ! prefs.getBoolPref( item.getAttribute( "name" ) );
    prefs.setBoolPref( item.getAttribute( "value" ), setting );
    item.setAttribute( "checked", setting ? "true" : "false" );
}
